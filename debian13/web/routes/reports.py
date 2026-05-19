"""
GateKeeper - 报表管理路由
"""

from flask import Blueprint, render_template, jsonify, request, send_file
from flask_login import login_required
from datetime import datetime, timedelta
import io

from config.logging_config import get_logger
from reports.report_generator import ReportGenerator
from web.routes.auth import admin_required
from web.app import _safe_error_message

logger = get_logger("web.reports")

reports_bp = Blueprint("reports", __name__)


@reports_bp.route("/")
@login_required
def index():
    """报表页面"""
    return render_template("reports.html", title="报表管理")


@reports_bp.route("/api/generate", methods=["POST"])
@admin_required
def api_generate():
    """生成报表"""
    report_type = request.json.get("type", "daily") if request.is_json else "daily"
    date_from = request.json.get("date_from", "") if request.is_json else ""
    date_to = request.json.get("date_to", "") if request.is_json else ""

    try:
        generator = ReportGenerator()

        if report_type == "daily":
            result = generator.generate_daily_report()
        elif report_type == "security":
            result = generator.generate_security_report(
                date_from=date_from,
                date_to=date_to,
            )
        elif report_type == "traffic":
            result = generator.generate_traffic_report(
                date_from=date_from,
                date_to=date_to,
            )
        else:
            return jsonify({"status": "error", "message": "未知报表类型"}), 400

        return jsonify({"status": "ok", "data": result})

    except Exception as e:
        logger.error("生成报表失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


@reports_bp.route("/api/export/pdf", methods=["POST"])
@admin_required
def api_export_pdf():
    """导出PDF报表"""
    report_type = request.json.get("type", "daily") if request.is_json else "daily"

    try:
        # 先检查 reportlab 是否可用
        try:
            import reportlab
        except ImportError:
            return jsonify({"status": "error", "message": "reportlab 未安装，无法生成PDF。请执行: pip3 install reportlab"}), 500

        from reports.pdf_export import PDFExporter
        exporter = PDFExporter()

        if report_type == "daily":
            pdf_data = exporter.export_daily_report()
        elif report_type == "security":
            pdf_data = exporter.export_daily_report()  # 复用日报模板
        elif report_type == "traffic":
            pdf_data = exporter.export_daily_report()
        else:
            pdf_data = exporter.export_custom_report(report_type)

        if pdf_data:
            return send_file(
                io.BytesIO(pdf_data),
                mimetype="application/pdf",
                as_attachment=True,
                download_name="gatekeeper_report_{}_{}.pdf".format(report_type, datetime.now().strftime('%Y%m%d')),
            )
        return jsonify({"status": "error", "message": "PDF生成失败，请查看日志"}), 500

    except Exception as e:
        logger.error("导出PDF失败: {}".format(e))
        return jsonify({"status": "error", "message": "导出PDF失败: {}".format(str(e))}), 500


@reports_bp.route("/api/list")
@login_required
def api_list():
    """获取报表列表"""
    try:
        generator = ReportGenerator()
        reports = generator.list_reports()
        return jsonify({"status": "ok", "data": reports})
    except Exception as e:
        return jsonify(_safe_error_message(e)), 500
