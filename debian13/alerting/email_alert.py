"""
GateKeeper - 邮件告警
通过SMTP发送安全告警邮件
"""

import smtplib
import threading
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.utils import formataddr, formatdate
from typing import Dict, List, Optional, Any
from datetime import datetime

from config.settings import settings
from config.logging_config import get_logger

logger = get_logger("email_alert")


class EmailAlerter:
    """
    邮件告警发送器
    通过SMTP协议发送安全告警邮件
    """

    def __init__(self):
        self._enabled = settings.alert.email_enabled
        self._smtp_host = settings.alert.smtp_host
        self._smtp_port = settings.alert.smtp_port
        self._smtp_user = settings.alert.smtp_user
        self._smtp_password = settings.alert.smtp_password
        self._smtp_tls = settings.alert.smtp_use_tls
        self._sender = settings.alert.email_sender
        self._recipients = settings.alert.email_recipients
        self._subject_prefix = settings.alert.email_subject_prefix

        # 邮件模板
        self._templates = self._load_templates()

        logger.info(
            "邮件告警器初始化: enabled={}, recipients={}".format(
                self._enabled, len(self._recipients)
            )
        )

    def _load_templates(self) -> Dict[str, str]:
        """加载邮件模板"""
        return {
            "alert": """
<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body style="font-family: Arial, sans-serif; color: #333;">
<div style="max-width: 600px; margin: 0 auto; padding: 20px;">
    <div style="background: #1e293b; color: white; padding: 20px; border-radius: 8px 8px 0 0;">
        <h1 style="margin: 0;">GateKeeper 安全告警</h1>
    </div>
    <div style="background: #f8fafc; padding: 20px; border: 1px solid #e2e8f0;">
        <h2 style="color: {level_color};">{title}</h2>
        <table style="width: 100%; border-collapse: collapse;">
            <tr><td style="padding: 8px; border-bottom: 1px solid #e2e8f0; font-weight: bold;">级别</td>
                <td style="padding: 8px; border-bottom: 1px solid #e2e8f0;">{level}</td></tr>
            <tr><td style="padding: 8px; border-bottom: 1px solid #e2e8f0; font-weight: bold;">来源</td>
                <td style="padding: 8px; border-bottom: 1px solid #e2e8f0;">{source}</td></tr>
            <tr><td style="padding: 8px; border-bottom: 1px solid #e2e8f0; font-weight: bold;">源IP</td>
                <td style="padding: 8px; border-bottom: 1px solid #e2e8f0;">{source_ip}</td></tr>
            <tr><td style="padding: 8px; border-bottom: 1px solid #e2e8f0; font-weight: bold;">时间</td>
                <td style="padding: 8px; border-bottom: 1px solid #e2e8f0;">{timestamp}</td></tr>
        </table>
        <p style="margin-top: 16px;">{description}</p>
    </div>
    <div style="background: #f1f5f9; padding: 12px; border-radius: 0 0 8px 8px; font-size: 12px; color: #64748b;">
        此邮件由 GateKeeper 自动发送，请勿直接回复。
    </div>
</div>
</body>
</html>
""",
            "summary": """
安全告警摘要
============

时间范围: {time_range}
告警总数: {total_alerts}
严重告警: {critical_count}
高危告警: {high_count}
中危告警: {medium_count}
低危告警: {low_count}

详细信息请登录 GateKeeper 管理面板查看。
""",
        }

    def send_alert(
        self,
        title: str,
        level: str,
        source: str,
        description: str = "",
        source_ip: str = "",
        dest_ip: str = "",
        metadata: Optional[Dict] = None,
    ) -> bool:
        """
        发送告警邮件

        Args:
            title: 告警标题
            level: 告警级别
            source: 告警来源
            description: 告警描述
            source_ip: 源IP
            dest_ip: 目标IP
            metadata: 附加元数据

        Returns:
            是否发送成功
        """
        if not self._enabled:
            logger.debug("邮件告警未启用")
            return False

        if not self._recipients:
            logger.warning("邮件告警收件人列表为空")
            return False

        level_colors = {
            "critical": "#dc2626",
            "high": "#f59e0b",
            "medium": "#0ea5e9",
            "low": "#64748b",
        }

        # 渲染模板
        html_content = self._templates["alert"].format(
            title=title,
            level=level.upper(),
            level_color=level_colors.get(level, "#64748b"),
            source=source,
            source_ip=source_ip or "N/A",
            dest_ip=dest_ip or "N/A",
            description=description or "无详细描述",
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        )

        subject = "{} [{}] {}".format(self._subject_prefix, level.upper(), title)

        # 在后台线程中发送
        thread = threading.Thread(
            target=self._send_email,
            args=(subject, html_content),
            daemon=True,
        )
        thread.start()

        return True

    def send_summary(self, summary: Dict[str, Any]) -> bool:
        """发送告警摘要邮件"""
        if not self._enabled or not self._recipients:
            return False

        text_content = self._templates["summary"].format(
            time_range=summary.get("time_range", "最近24小时"),
            total_alerts=summary.get("total", 0),
            critical_count=summary.get("critical", 0),
            high_count=summary.get("high", 0),
            medium_count=summary.get("medium", 0),
            low_count=summary.get("low", 0),
        )

        subject = "{} 安全告警摘要".format(self._subject_prefix)

        thread = threading.Thread(
            target=self._send_email,
            args=(subject, text_content, False),
            daemon=True,
        )
        thread.start()

        return True

    def _send_email(
        self,
        subject: str,
        content: str,
        is_html: bool = True,
    ):
        """发送邮件（在后台线程中执行）"""
        try:
            msg = MIMEMultipart("alternative")
            msg["From"] = formataddr(("GateKeeper", self._sender))
            msg["To"] = ", ".join(self._recipients)
            msg["Date"] = formatdate(localtime=True)
            msg["Subject"] = subject

            msg.attach(MIMEText(content, "html" if is_html else "plain", "utf-8"))

            if self._smtp_tls:
                server = smtplib.SMTP(self._smtp_host, self._smtp_port, timeout=30)
                server.starttls()
            else:
                server = smtplib.SMTP(self._smtp_host, self._smtp_port, timeout=30)

            if self._smtp_user and self._smtp_password:
                server.login(self._smtp_user, self._smtp_password)

            server.sendmail(self._sender, self._recipients, msg.as_string())
            server.quit()

            logger.info("告警邮件已发送: {}".format(subject))

        except Exception as e:
            logger.error("发送邮件失败: {}".format(e))

    def test_connection(self) -> Dict[str, Any]:
        """测试SMTP连接"""
        try:
            if self._smtp_tls:
                server = smtplib.SMTP(self._smtp_host, self._smtp_port, timeout=10)
                server.starttls()
            else:
                server = smtplib.SMTP(self._smtp_host, self._smtp_port, timeout=10)

            if self._smtp_user and self._smtp_password:
                server.login(self._smtp_user, self._smtp_password)

            server.quit()
            return {"status": "ok", "message": "SMTP连接测试成功"}

        except Exception as e:
            return {"status": "error", "message": "SMTP连接测试失败: {}".format(e)}
