"""
GateKeeper - PDF导出
使用reportlab生成PDF格式的安全报表
"""

import io
from typing import Dict, Any, Optional
from datetime import datetime

from config.logging_config import get_logger

logger = get_logger("pdf_export")


class PDFExporter:
    """
    PDF报表导出器
    使用reportlab生成专业的PDF安全报表
    """

    def __init__(self):
        logger.info("PDF导出器初始化完成")

    def export_daily_report(self) -> Optional[bytes]:
        """
        导出每日安全报告为PDF

        Returns:
            PDF二进制数据或None
        """
        try:
            from reportlab.lib.pagesizes import A4
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib.units import inch, mm
            from reportlab.lib.colors import HexColor, black, white
            from reportlab.platypus import (
                SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
                PageBreak, HRFlowable
            )
            from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT

            buffer = io.BytesIO()
            doc = SimpleDocTemplate(
                buffer,
                pagesize=A4,
                rightMargin=50,
                leftMargin=50,
                topMargin=50,
                bottomMargin=50,
            )

            styles = getSampleStyleSheet()

            # 自定义样式
            title_style = ParagraphStyle(
                "CustomTitle",
                parent=styles["Title"],
                fontSize=24,
                textColor=HexColor("#1e293b"),
                spaceAfter=6,
                alignment=TA_CENTER,
            )
            subtitle_style = ParagraphStyle(
                "CustomSubtitle",
                parent=styles["Normal"],
                fontSize=12,
                textColor=HexColor("#64748b"),
                alignment=TA_CENTER,
                spaceAfter=20,
            )
            heading_style = ParagraphStyle(
                "CustomHeading",
                parent=styles["Heading2"],
                fontSize=16,
                textColor=HexColor("#2563eb"),
                spaceBefore=16,
                spaceAfter=8,
            )
            body_style = ParagraphStyle(
                "CustomBody",
                parent=styles["Normal"],
                fontSize=10,
                leading=14,
                textColor=HexColor("#334155"),
            )

            elements = []

            # 标题
            elements.append(Paragraph("GateKeeper", title_style))
            elements.append(Paragraph("每日安全报告", subtitle_style))
            elements.append(HRFlowable(width="100%", thickness=1, color=HexColor("#e2e8f0")))
            elements.append(Spacer(1, 12))

            # 报告信息
            now = datetime.now()
            info_data = [
                ["报告日期", now.strftime("%Y-%m-%d")],
                ["生成时间", now.strftime("%Y-%m-%d %H:%M:%S")],
                ["报告类型", "每日安全摘要"],
            ]
            info_table = Table(info_data, colWidths=[120, 300])
            info_table.setStyle(TableStyle([
                ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 10),
                ("TEXTCOLOR", (0, 0), (0, -1), HexColor("#64748b")),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
            ]))
            elements.append(info_table)
            elements.append(Spacer(1, 20))

            # 告警摘要
            elements.append(Paragraph("告警摘要", heading_style))
            alert_data = [
                ["级别", "数量"],
                ["严重 (Critical)", "0"],
                ["高危 (High)", "0"],
                ["中危 (Medium)", "0"],
                ["低危 (Low)", "0"],
            ]
            alert_table = Table(alert_data, colWidths=[200, 100])
            alert_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), HexColor("#f1f5f9")),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 10),
                ("GRID", (0, 0), (-1, -1), 0.5, HexColor("#e2e8f0")),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("TEXTCOLOR", (0, 1), (0, 1), HexColor("#dc2626")),
                ("TEXTCOLOR", (0, 2), (0, 2), HexColor("#f59e0b")),
                ("TEXTCOLOR", (0, 3), (0, 3), HexColor("#0ea5e9")),
                ("TEXTCOLOR", (0, 4), (0, 4), HexColor("#64748b")),
            ]))
            elements.append(alert_table)
            elements.append(Spacer(1, 20))

            # 流量摘要
            elements.append(Paragraph("流量摘要", heading_style))
            traffic_data = [
                ["指标", "数值"],
                ["总数据包", "0"],
                ["总字节数", "0 B"],
                ["异常数据包", "0"],
                ["异常率", "0%"],
            ]
            traffic_table = Table(traffic_data, colWidths=[200, 100])
            traffic_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), HexColor("#f1f5f9")),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 10),
                ("GRID", (0, 0), (-1, -1), 0.5, HexColor("#e2e8f0")),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
            ]))
            elements.append(traffic_table)
            elements.append(Spacer(1, 20))

            # 页脚
            elements.append(Spacer(1, 40))
            elements.append(HRFlowable(width="100%", thickness=0.5, color=HexColor("#e2e8f0")))
            elements.append(Paragraph(
                "此报告由 GateKeeper AI安全网络防御系统自动生成",
                ParagraphStyle("Footer", parent=body_style, alignment=TA_CENTER, textColor=HexColor("#94a3b8"), fontSize=9)
            ))

            doc.build(elements)
            pdf_data = buffer.getvalue()
            buffer.close()

            logger.info("PDF报告生成成功")
            return pdf_data

        except ImportError:
            logger.error("reportlab未安装，无法生成PDF")
            return None
        except Exception as e:
            logger.error("PDF生成失败: {}".format(e))
            return None

    def export_custom_report(self, report_type: str) -> Optional[bytes]:
        """
        导出自定义报表

        Args:
            report_type: 报表类型

        Returns:
            PDF二进制数据或None
        """
        # 目前使用通用模板，后续可扩展
        return self.export_daily_report()
