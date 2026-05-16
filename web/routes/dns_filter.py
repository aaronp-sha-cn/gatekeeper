"""
GateKeeper - DNS过滤管理路由
提供DNS过滤规则的API接口
"""

from flask import Blueprint, jsonify, request, render_template, Response
from flask_login import login_required

from web.routes.auth import admin_required

from config.logging_config import get_logger
from core.audit import log_web_action
from security.dns_filter import get_dns_filter
from web.app import _safe_error_message

logger = get_logger("dns_filter_routes")

dns_filter_bp = Blueprint("dns_filter", __name__, url_prefix="/dns-filter")


@dns_filter_bp.route("/")
@login_required
def index():
    """DNS过滤管理页面"""
    return render_template("dns_filter.html")


@dns_filter_bp.route("/api/rules")
@login_required
def get_rules():
    """获取规则列表"""
    try:
        engine = get_dns_filter()
        rule_type = request.args.get("rule_type")
        category = request.args.get("category")
        enabled_only = request.args.get("enabled_only", "false").lower() == "true"

        rules = engine.get_rules(
            rule_type=rule_type,
            category=category,
            enabled_only=enabled_only,
        )
        return jsonify({
            "status": "ok",
            "data": {
                "rules": rules,
                "total": len(rules),
            }
        })
    except Exception as e:
        logger.error("获取DNS过滤规则失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


@dns_filter_bp.route("/api/rules", methods=["POST"])
@admin_required
def add_rule():
    """添加规则"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({"status": "error", "message": "请求数据不能为空"}), 400

        name = data.get("name", "").strip()
        domain = data.get("domain", "").strip()
        rule_type = data.get("rule_type", "blacklist").strip()
        category = data.get("category", "custom").strip()
        action = data.get("action", "block").strip()
        redirect_to = data.get("redirect_to", "").strip()
        enabled = data.get("enabled", True)
        description = data.get("description", "").strip()

        # 参数校验
        if not name:
            return jsonify({"status": "error", "message": "规则名称不能为空"}), 400
        if not domain:
            return jsonify({"status": "error", "message": "域名不能为空"}), 400

        valid_types = ["whitelist", "blacklist", "category"]
        if rule_type not in valid_types:
            return jsonify({"status": "error", "message": "无效的规则类型，可选: {}".format(", ".join(valid_types))}), 400

        valid_actions = ["block", "redirect", "sinkhole"]
        if action not in valid_actions:
            return jsonify({"status": "error", "message": "无效的动作，可选: {}".format(", ".join(valid_actions))}), 400

        valid_categories = [
            "adult", "gambling", "malware", "phishing", "ad", "tracking",
            "social_media", "mining", "c2", "custom"
        ]
        if category not in valid_categories:
            return jsonify({"status": "error", "message": "无效的分类，可选: {}".format(", ".join(valid_categories))}), 400

        if action == "redirect" and not redirect_to:
            return jsonify({"status": "error", "message": "重定向动作需要提供重定向IP地址"}), 400

        engine = get_dns_filter()
        rule = engine.add_rule(
            name=name,
            domain=domain,
            rule_type=rule_type,
            category=category,
            action=action,
            redirect_to=redirect_to,
            enabled=enabled,
            description=description,
        )

        log_web_action(
            action="add_rule",
            module="dns_filter",
            detail="添加DNS过滤规则: {} (域名: {}, 类型: {}, 动作: {})".format(
                name, domain, rule_type, action
            ),
        )

        return jsonify({
            "status": "ok",
            "message": "规则添加成功",
            "data": rule.to_dict(),
        })
    except Exception as e:
        logger.error("添加DNS过滤规则失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


@dns_filter_bp.route("/api/rules/<int:rule_id>", methods=["DELETE"])
@admin_required
def delete_rule(rule_id):
    """删除规则"""
    try:
        engine = get_dns_filter()
        success = engine.remove_rule(rule_id)

        if not success:
            return jsonify({"status": "error", "message": "规则 {} 不存在".format(rule_id)}), 404

        log_web_action(
            action="delete_rule",
            module="dns_filter",
            detail="删除DNS过滤规则: {}".format(rule_id),
        )

        return jsonify({
            "status": "ok",
            "message": "规则删除成功",
        })
    except Exception as e:
        logger.error("删除DNS过滤规则失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


@dns_filter_bp.route("/api/rules/<int:rule_id>/toggle", methods=["POST"])
@admin_required
def toggle_rule(rule_id):
    """启用/禁用规则"""
    try:
        data = request.get_json()
        if not data or "enabled" not in data:
            return jsonify({"status": "error", "message": "请提供enabled参数"}), 400

        enabled = bool(data["enabled"])
        engine = get_dns_filter()
        success = engine.toggle_rule(rule_id, enabled)

        if not success:
            return jsonify({"status": "error", "message": "规则 {} 不存在".format(rule_id)}), 404

        log_web_action(
            action="toggle_rule",
            module="dns_filter",
            detail="{}DNS过滤规则: {}".format("启用" if enabled else "禁用", rule_id),
        )

        return jsonify({
            "status": "ok",
            "message": "规则已{}".format("启用" if enabled else "禁用"),
        })
    except Exception as e:
        logger.error("切换DNS过滤规则状态失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


@dns_filter_bp.route("/api/stats")
@login_required
def get_stats():
    """获取统计信息"""
    try:
        engine = get_dns_filter()
        stats = engine.get_stats()
        return jsonify({
            "status": "ok",
            "data": stats,
        })
    except Exception as e:
        logger.error("获取DNS过滤统计失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


@dns_filter_bp.route("/api/logs")
@login_required
def get_logs():
    """获取DNS查询日志"""
    try:
        limit = request.args.get("limit", 100, type=int)
        offset = request.args.get("offset", 0, type=int)
        domain = request.args.get("domain")
        action = request.args.get("action")
        client_ip = request.args.get("client_ip")

        engine = get_dns_filter()
        result = engine.get_logs(
            limit=limit,
            offset=offset,
            domain=domain,
            action=action,
            client_ip=client_ip,
        )

        return jsonify({
            "status": "ok",
            "data": result,
        })
    except Exception as e:
        logger.error("获取DNS查询日志失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


@dns_filter_bp.route("/api/test", methods=["POST"])
@admin_required
def test_query():
    """测试DNS查询"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({"status": "error", "message": "请求数据不能为空"}), 400

        domain = data.get("domain", "").strip()
        query_type = data.get("query_type", "A").strip()
        client_ip = data.get("client_ip", "127.0.0.1").strip()

        if not domain:
            return jsonify({"status": "error", "message": "域名不能为空"}), 400

        valid_query_types = ["A", "AAAA", "CNAME", "MX", "TXT", "NS"]
        if query_type.upper() not in valid_query_types:
            return jsonify({"status": "error", "message": "无效的查询类型，可选: {}".format(", ".join(valid_query_types))}), 400

        engine = get_dns_filter()
        result = engine.inspect_query(
            domain=domain,
            query_type=query_type.upper(),
            client_ip=client_ip,
        )

        log_web_action(
            action="test_query",
            module="dns_filter",
            detail="测试DNS查询: {} (类型: {})".format(domain, query_type),
        )

        return jsonify({
            "status": "ok",
            "data": result,
        })
    except Exception as e:
        logger.error("测试DNS查询失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


@dns_filter_bp.route("/api/import", methods=["POST"])
@admin_required
def import_rules():
    """批量导入规则"""
    try:
        data = request.get_json()
        if not data or "rules" not in data:
            return jsonify({"status": "error", "message": "请提供rules参数（规则列表）"}), 400

        rules_data = data["rules"]
        if not isinstance(rules_data, list) or len(rules_data) == 0:
            return jsonify({"status": "error", "message": "rules必须为非空列表"}), 400

        engine = get_dns_filter()
        result = engine.import_rules(rules_data)

        log_web_action(
            action="import_rules",
            module="dns_filter",
            detail="批量导入DNS规则: 成功={}, 失败={}".format(
                result["success"], result["failed"]
            ),
        )

        return jsonify({
            "status": "ok",
            "message": "导入完成: 成功 {} 条, 失败 {} 条".format(
                result["success"], result["failed"]
            ),
            "data": result,
        })
    except Exception as e:
        logger.error("导入DNS规则失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


@dns_filter_bp.route("/api/export")
@login_required
def export_rules():
    """导出规则"""
    try:
        rule_type = request.args.get("rule_type")
        category = request.args.get("category")

        engine = get_dns_filter()
        rules = engine.export_rules(rule_type=rule_type, category=category)

        log_web_action(
            action="export_rules",
            module="dns_filter",
            detail="导出DNS规则: {} 条".format(len(rules)),
        )

        return jsonify({
            "status": "ok",
            "data": {
                "rules": rules,
                "total": len(rules),
            }
        })
    except Exception as e:
        logger.error("导出DNS规则失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


@dns_filter_bp.route("/api/export/download")
@login_required
def export_rules_download():
    """导出规则为JSON文件下载"""
    try:
        import json

        rule_type = request.args.get("rule_type")
        category = request.args.get("category")

        engine = get_dns_filter()
        rules = engine.export_rules(rule_type=rule_type, category=category)

        content = json.dumps(rules, ensure_ascii=False, indent=2)

        log_web_action(
            action="export_rules",
            module="dns_filter",
            detail="下载DNS规则文件: {} 条".format(len(rules)),
        )

        return Response(
            content,
            mimetype="application/json",
            headers={"Content-Disposition": "attachment; filename=dns_filter_rules.json"},
        )
    except Exception as e:
        logger.error("下载DNS规则文件失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


@dns_filter_bp.route("/api/clear-logs", methods=["POST"])
@admin_required
def clear_logs():
    """清理日志"""
    try:
        data = request.get_json() or {}
        days = data.get("days", 30)

        if not isinstance(days, int) or days < 1:
            return jsonify({"status": "error", "message": "days必须为正整数"}), 400

        engine = get_dns_filter()
        result = engine.clear_logs(days=days)

        log_web_action(
            action="clear_logs",
            module="dns_filter",
            detail="清理DNS查询日志: 保留 {} 天".format(days),
        )

        return jsonify({
            "status": "ok",
            "message": result["message"],
            "data": result,
        })
    except Exception as e:
        logger.error("清理DNS日志失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500
