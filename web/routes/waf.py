"""
GateKeeper - WAF管理路由
提供Web应用防火墙的API接口
"""

from flask import Blueprint, jsonify, request, render_template
from flask_login import login_required, current_user

from web.routes.auth import admin_required

from config.logging_config import get_logger
from core.audit import log_web_action
from security.waf_engine import get_waf_engine
from web.app import _safe_error_message

logger = get_logger("waf_routes")

waf_bp = Blueprint("waf", __name__, url_prefix="/waf")


@waf_bp.route("/")
@login_required
def index():
    """WAF管理页面"""
    return render_template("waf.html")


@waf_bp.route("/api/rules")
@login_required
def get_rules():
    """获取规则列表"""
    try:
        engine = get_waf_engine()
        rules = engine.get_rules()
        return jsonify({
            "status": "ok",
            "data": {
                "rules": rules,
                "total": len(rules),
            }
        })
    except Exception as e:
        logger.error(f"获取WAF规则失败: {e}")
        return jsonify(_safe_error_message(e)), 500


@waf_bp.route("/api/rules", methods=["POST"])
@admin_required
def add_rule():
    """添加规则"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({"status": "error", "message": "请求数据不能为空"}), 400

        name = data.get("name", "").strip()
        rule_type = data.get("rule_type", "").strip()
        pattern = data.get("pattern", "").strip()
        action = data.get("action", "block").strip()
        severity = data.get("severity", "medium").strip()
        description = data.get("description", "").strip()

        # 参数校验
        if not name:
            return jsonify({"status": "error", "message": "规则名称不能为空"}), 400
        if not rule_type:
            return jsonify({"status": "error", "message": "规则类型不能为空"}), 400
        if not pattern:
            return jsonify({"status": "error", "message": "匹配模式不能为空"}), 400

        valid_types = [
            "sql_injection", "xss", "csrf", "path_traversal",
            "file_upload", "rce", "bot", "rate_limit", "custom"
        ]
        if rule_type not in valid_types:
            return jsonify({"status": "error", "message": f"无效的规则类型，可选: {', '.join(valid_types)}"}), 400

        valid_actions = ["block", "log", "allow"]
        if action not in valid_actions:
            return jsonify({"status": "error", "message": f"无效的动作，可选: {', '.join(valid_actions)}"}), 400

        valid_severities = ["low", "medium", "high", "critical"]
        if severity not in valid_severities:
            return jsonify({"status": "error", "message": f"无效的严重程度，可选: {', '.join(valid_severities)}"}), 400

        # 验证正则表达式
        import re
        try:
            re.compile(pattern)
        except re.error as e:
            return jsonify({"status": "error", "message": f"正则表达式无效: {e}"}), 400

        engine = get_waf_engine()
        rule = engine.add_rule(
            name=name,
            rule_type=rule_type,
            pattern=pattern,
            action=action,
            severity=severity,
            description=description,
        )

        log_web_action(
            action="add_rule",
            module="waf",
            detail=f"添加WAF规则: {name} (类型: {rule_type}, 动作: {action})",
        )

        return jsonify({
            "status": "ok",
            "message": "规则添加成功",
            "data": rule.to_dict(),
        })
    except Exception as e:
        logger.error(f"添加WAF规则失败: {e}")
        return jsonify(_safe_error_message(e)), 500


@waf_bp.route("/api/rules/<int:rule_id>", methods=["PUT"])
@admin_required
def update_rule(rule_id):
    """更新规则"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({"status": "error", "message": "请求数据不能为空"}), 400

        # 验证正则表达式（如果提供了pattern）
        if "pattern" in data:
            import re
            try:
                re.compile(data["pattern"])
            except re.error as e:
                return jsonify({"status": "error", "message": f"正则表达式无效: {e}"}), 400

        engine = get_waf_engine()
        success = engine.update_rule(rule_id, **data)

        if not success:
            return jsonify({"status": "error", "message": f"规则 {rule_id} 不存在"}), 404

        rule = engine.get_rule(rule_id)

        log_web_action(
            action="update_rule",
            module="waf",
            detail=f"更新WAF规则: {rule_id}",
        )

        return jsonify({
            "status": "ok",
            "message": "规则更新成功",
            "data": rule.to_dict() if rule else None,
        })
    except Exception as e:
        logger.error(f"更新WAF规则失败: {e}")
        return jsonify(_safe_error_message(e)), 500


@waf_bp.route("/api/rules/<int:rule_id>", methods=["DELETE"])
@admin_required
def delete_rule(rule_id):
    """删除规则"""
    try:
        engine = get_waf_engine()
        success = engine.remove_rule(rule_id)

        if not success:
            return jsonify({"status": "error", "message": f"规则 {rule_id} 不存在"}), 404

        log_web_action(
            action="delete_rule",
            module="waf",
            detail=f"删除WAF规则: {rule_id}",
        )

        return jsonify({
            "status": "ok",
            "message": "规则删除成功",
        })
    except Exception as e:
        logger.error(f"删除WAF规则失败: {e}")
        return jsonify(_safe_error_message(e)), 500


@waf_bp.route("/api/rules/<int:rule_id>/toggle", methods=["POST"])
@admin_required
def toggle_rule(rule_id):
    """启用/禁用规则"""
    try:
        data = request.get_json()
        if not data or "enabled" not in data:
            return jsonify({"status": "error", "message": "请提供enabled参数"}), 400

        enabled = bool(data["enabled"])
        engine = get_waf_engine()
        success = engine.toggle_rule(rule_id, enabled)

        if not success:
            return jsonify({"status": "error", "message": f"规则 {rule_id} 不存在"}), 404

        log_web_action(
            action="toggle_rule",
            module="waf",
            detail=f"{'启用' if enabled else '禁用'}WAF规则: {rule_id}",
        )

        return jsonify({
            "status": "ok",
            "message": f"规则已{'启用' if enabled else '禁用'}",
        })
    except Exception as e:
        logger.error(f"切换WAF规则状态失败: {e}")
        return jsonify(_safe_error_message(e)), 500


@waf_bp.route("/api/stats")
@login_required
def get_stats():
    """获取统计信息"""
    try:
        engine = get_waf_engine()
        stats = engine.get_stats()
        return jsonify({
            "status": "ok",
            "data": stats,
        })
    except Exception as e:
        logger.error(f"获取WAF统计失败: {e}")
        return jsonify(_safe_error_message(e)), 500


@waf_bp.route("/api/logs")
@login_required
def get_logs():
    """获取WAF日志（分页）"""
    try:
        page = request.args.get("page", 1, type=int)
        per_page = request.args.get("per_page", 50, type=int)

        engine = get_waf_engine()
        result = engine.get_logs(page=page, per_page=per_page)

        return jsonify({
            "status": "ok",
            "data": result,
        })
    except Exception as e:
        logger.error(f"获取WAF日志失败: {e}")
        return jsonify(_safe_error_message(e)), 500


@waf_bp.route("/api/test", methods=["POST"])
@admin_required
def test_request():
    """测试URL/请求体是否触发规则"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({"status": "error", "message": "请求数据不能为空"}), 400

        method = data.get("method", "GET").upper()
        url = data.get("url", "/")
        headers = data.get("headers", {})
        body = data.get("body", "")
        client_ip = data.get("client_ip", "127.0.0.1")

        if not url:
            return jsonify({"status": "error", "message": "URL不能为空"}), 400

        engine = get_waf_engine()
        decision = engine.test_request(
            method=method,
            url=url,
            headers=headers,
            body=body,
            client_ip=client_ip,
        )

        log_web_action(
            action="test_request",
            module="waf",
            detail=f"测试WAF规则: {method} {url}",
        )

        return jsonify({
            "status": "ok",
            "data": decision.to_dict(),
        })
    except Exception as e:
        logger.error(f"WAF测试请求失败: {e}")
        return jsonify(_safe_error_message(e)), 500
