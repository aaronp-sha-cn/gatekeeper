"""
GateKeeper - Webhook告警
通过HTTP Webhook发送安全告警通知
"""

import json
import threading
import urllib.request
import urllib.error
from typing import Dict, List, Optional, Any
from datetime import datetime

from config.settings import settings
from config.logging_config import get_logger

logger = get_logger("webhook_alert")


class WebhookAlerter:
    """
    Webhook告警发送器
    通过HTTP POST请求将告警推送到配置的Webhook URL
    支持Slack、Discord、企业微信等Webhook格式
    """

    def __init__(self):
        self._enabled = settings.alert.webhook_enabled
        self._urls = settings.alert.webhook_urls
        self._timeout = settings.alert.webhook_timeout

        logger.info(
            "Webhook告警器初始化: enabled={}, urls={}".format(
                self._enabled, len(self._urls)
            )
        )

    def send_alert(
        self,
        title: str,
        level: str,
        source: str,
        description: str = "",
        source_ip: str = "",
        dest_ip: str = "",
        metadata: Optional[Dict] = None,
    ) -> Dict[str, Any]:
        """
        发送告警到所有配置的Webhook

        Args:
            title: 告警标题
            level: 告警级别
            source: 告警来源
            description: 告警描述
            source_ip: 源IP
            dest_ip: 目标IP
            metadata: 附加元数据

        Returns:
            发送结果
        """
        if not self._enabled:
            return {"status": "disabled", "message": "Webhook告警未启用"}

        if not self._urls:
            return {"status": "error", "message": "未配置Webhook URL"}

        # 构建告警payload
        payload = {
            "text": "[{}] {}".format(level.upper(), title),
            "attachments": [
                {
                    "title": title,
                    "color": self._level_to_color(level),
                    "fields": [
                        {"title": "级别", "value": level.upper(), "short": True},
                        {"title": "来源", "value": source, "short": True},
                        {"title": "源IP", "value": source_ip or "N/A", "short": True},
                        {"title": "时间", "value": datetime.now().isoformat(), "short": True},
                    ],
                    "text": description,
                    "footer": "GateKeeper",
                    "ts": datetime.now().timestamp(),
                }
            ],
            "metadata": metadata or {},
        }

        # 发送到所有URL
        results = []
        for url in self._urls:
            thread = threading.Thread(
                target=self._send_webhook,
                args=(url, payload),
                daemon=True,
            )
            thread.start()
            results.append({"url": url, "status": "sent"})

        return {"status": "ok", "results": results}

    def send_custom(
        self,
        url: str,
        payload: Dict[str, Any],
        headers: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        """
        发送自定义Webhook

        Args:
            url: Webhook URL
            payload: 自定义数据
            headers: 自定义请求头

        Returns:
            发送结果
        """
        try:
            data = json.dumps(payload).encode("utf-8")
            req = urllib.request.Request(
                url,
                data=data,
                headers={
                    "Content-Type": "application/json",
                    **(headers or {}),
                },
                method="POST",
            )

            with urllib.request.urlopen(req, timeout=self._timeout) as response:
                status_code = response.status
                return {
                    "status": "ok",
                    "url": url,
                    "status_code": status_code,
                }

        except urllib.error.HTTPError as e:
            logger.error("Webhook HTTP错误: {} - {}".format(e.code, e.reason))
            return {
                "status": "error",
                "url": url,
                "status_code": e.code,
                "message": e.reason,
            }
        except Exception as e:
            logger.error("Webhook发送失败: {}".format(e))
            return {
                "status": "error",
                "url": url,
                "message": str(e),
            }

    def _send_webhook(self, url: str, payload: Dict[str, Any]):
        """发送Webhook请求（在后台线程中执行）"""
        try:
            self.send_custom(url, payload)
            logger.debug("Webhook已发送: {}".format(url))
        except Exception as e:
            logger.error("Webhook发送失败: {}, {}".format(url, e))

    def _level_to_color(self, level: str) -> str:
        """将告警级别映射为颜色代码"""
        colors = {
            "critical": "#dc2626",
            "high": "#f59e0b",
            "medium": "#0ea5e9",
            "low": "#64748b",
        }
        return colors.get(level, "#64748b")

    def test_webhook(self, url: str) -> Dict[str, Any]:
        """测试Webhook连接"""
        test_payload = {
            "text": "[TEST] GateKeeper Webhook测试",
            "attachments": [
                {
                    "title": "Webhook连接测试",
                    "color": "#16a34a",
                    "text": "如果您看到此消息，说明Webhook配置正确。",
                    "footer": "GateKeeper",
                    "ts": datetime.now().timestamp(),
                }
            ],
        }
        return self.send_custom(url, test_payload)
