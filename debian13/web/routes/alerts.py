"""
GateKeeper - 告警管理路由
"""

from flask import Blueprint, render_template, jsonify, request
from flask_login import login_required, current_user
from datetime import datetime

from config.logging_config import get_logger, log_security_event
from core.database import db_manager
from core.models import Alert, AlertStatus
from web.routes.auth import admin_required
from web.app import _safe_error_message

logger = get_logger("web.alerts")

alerts_bp = Blueprint("alerts", __name__)


@alerts_bp.route("/")
@login_required
def index():
    """告警列表页面"""
    return render_template("alerts.html", title="告警管理")


@alerts_bp.route("/api/list")
@login_required
def api_list():
    """获取告警列表"""
    page = request.args.get("page", 1, type=int)
    per_page = request.args.get("per_page", 20, type=int)
    level = request.args.get("level", "")
    status = request.args.get("status", "")

    try:
        with db_manager.get_session() as session:
            query = session.query(Alert)

            if level:
                query = query.filter(Alert.level == level)
            if status:
                query = query.filter(Alert.status == status)

            total = query.count()
            alerts = (
                query.order_by(Alert.created_at.desc())
                .offset((page - 1) * per_page)
                .limit(per_page)
                .all()
            )

            return jsonify({
                "status": "ok",
                "data": {
                    "alerts": [
                        {
                            "id": a.id,
                            "title": a.title,
                            "description": a.description,
                            "level": a.level.value,
                            "status": a.status.value,
                            "source": a.source,
                            "source_ip": a.source_ip,
                            "dest_ip": a.dest_ip,
                            "port": a.port,
                            "protocol": a.protocol,
                            "severity_score": a.severity_score,
                            "created_at": a.created_at.isoformat() if a.created_at else None,
                            "resolved_at": a.resolved_at.isoformat() if a.resolved_at else None,
                        }
                        for a in alerts
                    ],
                    "total": total,
                    "page": page,
                    "per_page": per_page,
                    "total_pages": (total + per_page - 1) // per_page,
                },
            })
    except Exception as e:
        logger.error("获取告警列表失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


@alerts_bp.route("/api/<int:alert_id>/acknowledge", methods=["POST"])
@admin_required
def api_acknowledge(alert_id: int):
    """确认告警"""
    try:
        with db_manager.get_session() as session:
            alert = session.query(Alert).filter_by(id=alert_id).first()
            if not alert:
                return jsonify({"status": "not_found"}), 404

            alert.status = AlertStatus.ACKNOWLEDGED
            alert.assigned_to = current_user.id

            log_security_event(
                user=current_user.username,
                action="alert_acknowledge",
                resource=str(alert_id),
                result="success",
                message="确认告警: {}".format(alert.title)
            )

            return jsonify({"status": "ok", "alert_id": alert_id})
    except Exception as e:
        return jsonify(_safe_error_message(e)), 500


@alerts_bp.route("/api/<int:alert_id>/resolve", methods=["POST"])
@admin_required
def api_resolve(alert_id: int):
    """解决告警"""
    note = request.json.get("note", "") if request.is_json else ""

    try:
        with db_manager.get_session() as session:
            alert = session.query(Alert).filter_by(id=alert_id).first()
            if not alert:
                return jsonify({"status": "not_found"}), 404

            alert.status = AlertStatus.RESOLVED
            alert.resolved_at = datetime.now()
            alert.resolution_note = note
            alert.assigned_to = current_user.id

            log_security_event(
                user=current_user.username,
                action="alert_resolve",
                resource=str(alert_id),
                result="success",
                message="解决告警: {}".format(alert.title)
            )

            return jsonify({"status": "ok", "alert_id": alert_id})
    except Exception as e:
        return jsonify(_safe_error_message(e)), 500


@alerts_bp.route("/api/<int:alert_id>/ignore", methods=["POST"])
@admin_required
def api_ignore(alert_id: int):
    """忽略告警"""
    try:
        with db_manager.get_session() as session:
            alert = session.query(Alert).filter_by(id=alert_id).first()
            if not alert:
                return jsonify({"status": "not_found"}), 404

            alert.status = AlertStatus.IGNORED
            return jsonify({"status": "ok", "alert_id": alert_id})
    except Exception as e:
        return jsonify(_safe_error_message(e)), 500


@alerts_bp.route("/api/stats")
@login_required
def api_stats():
    """告警统计"""
    try:
        from sqlalchemy import func
        with db_manager.get_session() as session:
            by_level = (
                session.query(Alert.level, func.count(Alert.id))
                .group_by(Alert.level)
                .all()
            )
            by_status = (
                session.query(Alert.status, func.count(Alert.id))
                .group_by(Alert.status)
                .all()
            )

            return jsonify({
                "status": "ok",
                "data": {
                    "by_level": {l.value: c for l, c in by_level},
                    "by_status": {s.value: c for s, c in by_status},
                    "total": sum(c for _, c in by_level),
                },
            })
    except Exception as e:
        return jsonify(_safe_error_message(e)), 500
