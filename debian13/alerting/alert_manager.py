"""
GateKeeper - 告警管理器
统一管理所有告警通道，包括邮件、Webhook等
"""

import threading
import time
from typing import Dict, List, Optional, Any, Callable
from datetime import datetime, timedelta
from collections import deque

from config.settings import settings
from config.logging_config import get_logger
from core.database import db_manager
from core.models import Alert, AlertLevel, AlertStatus
from alerting.email_alert import EmailAlerter
from alerting.webhook_alert import WebhookAlerter

logger = get_logger("alert_manager")


class AlertManager:
    """
    告警管理器
    统一管理告警的创建、分发和聚合
    """

    def __init__(self):
        self._lock = threading.Lock()

        # 告警通道
        self._email_alerter = EmailAlerter()
        self._webhook_alerter = WebhookAlerter()

        # 告警冷却（避免重复告警）
        self._alert_cooldown: Dict[str, float] = {}
        self._cooldown_seconds = settings.alert.alert_cooldown

        # 告警聚合
        self._aggregation_buffer: deque = deque(maxlen=1000)
        self._aggregation_window = settings.alert.alert_aggregation_window
        self._aggregation_timer: Optional[threading.Thread] = None
        self._aggregation_running = False

        # 频率限制
        self._rate_counter: Dict[str, int] = {}
        self._max_per_minute = settings.alert.max_alerts_per_minute

        # 统计
        self._stats = {
            "total_sent": 0,
            "email_sent": 0,
            "webhook_sent": 0,
            "suppressed": 0,
            "aggregated": 0,
        }

        # 告警回调
        self._callbacks: List[Callable] = []

        # 注册SSE实时推送回调
        self._init_sse_callback()

        logger.info("告警管理器初始化完成")

    def _init_sse_callback(self):
        """初始化SSE事件总线回调，将告警推送到前端"""
        try:
            from web.routes.websocket import publish_alert
            self.register_callback(publish_alert)
            logger.info("SSE告警推送回调已注册")
        except Exception as e:
            logger.debug("SSE回调注册跳过（web模块未加载）: {}".format(e))

    def start(self):
        """启动告警聚合定时器"""
        if self._aggregation_running:
            return
        self._aggregation_running = True
        self._aggregation_timer = threading.Thread(
            target=self._run_aggregation_loop,
            daemon=True,
            name="alert-aggregation",
        )
        self._aggregation_timer.start()
        logger.info("告警聚合定时器已启动 (interval={}s)".format(self._aggregation_window))

    def _run_aggregation_loop(self):
        """告警聚合循环 - 定期处理聚合缓冲区"""
        while self._aggregation_running:
            time.sleep(self._aggregation_window)
            self._process_aggregation_buffer()

    def _process_aggregation_buffer(self):
        """处理聚合缓冲区中的告警"""
        if not self._aggregation_buffer:
            return

        with self._lock:
            if not self._aggregation_buffer:
                return

            # 取出所有缓冲的告警
            buffered_alerts = list(self._aggregation_buffer)
            self._aggregation_buffer.clear()

        if len(buffered_alerts) <= 1:
            # 单条告警直接分发
            return

        # 聚合多条相似告警
        logger.info("处理告警聚合: {} 条告警待聚合".format(len(buffered_alerts)))
        self._stats["aggregated"] += len(buffered_alerts) - 1

    def stop(self):
        """停止告警聚合定时器"""
        self._aggregation_running = False
        if self._aggregation_timer and self._aggregation_timer.is_alive():
            self._aggregation_timer.join(timeout=5)
        logger.info("告警聚合定时器已停止")

    def create_alert(
        self,
        title: str,
        level: str = "medium",
        source: str = "system",
        description: str = "",
        source_ip: str = "",
        dest_ip: str = "",
        port: Optional[int] = None,
        protocol: str = "",
        severity_score: Optional[float] = None,
        metadata: Optional[Dict] = None,
    ) -> Dict[str, Any]:
        """
        创建并分发告警

        Args:
            title: 告警标题
            level: 告警级别 (low/medium/high/critical)
            source: 告警来源
            description: 告警描述
            source_ip: 源IP
            dest_ip: 目标IP
            port: 端口
            protocol: 协议
            severity_score: 严重程度分数
            metadata: 附加元数据

        Returns:
            创建结果
        """
        # 检查冷却
        cooldown_key = "{}:{}:{}".format(source, source_ip, title)
        if self._is_on_cooldown(cooldown_key):
            self._stats["suppressed"] += 1
            logger.debug("告警被冷却抑制: {}".format(cooldown_key))
            return {"status": "suppressed", "reason": "cooldown"}

        # 检查频率限制
        if not self._check_rate_limit():
            self._stats["suppressed"] += 1
            logger.warning("告警频率超限，已抑制")
            return {"status": "suppressed", "reason": "rate_limit"}

        # 创建告警记录
        try:
            alert = Alert(
                title=title,
                description=description,
                level=AlertLevel(level),
                status=AlertStatus.NEW,
                source=source,
                source_ip=source_ip,
                dest_ip=dest_ip,
                port=port,
                protocol=protocol,
                severity_score=severity_score,
                metadata_json=metadata,
            )
            alert = db_manager.add(alert)

            # 更新冷却
            self._alert_cooldown[cooldown_key] = time.time()

            # 分发告警
            self._dispatch_alert(alert)

            # 触发回调（使用快照迭代，避免并发修改问题）
            for callback in list(self._callbacks):
                try:
                    callback(alert)
                except Exception as e:
                    logger.error("告警回调执行失败: {}".format(e))

            self._stats["total_sent"] += 1

            logger.info(
                "告警已创建: id={}, level={}, title={}, src={}".format(
                    alert.id, level, title, source_ip
                )
            )

            return {"status": "ok", "alert_id": alert.id}

        except Exception as e:
            logger.error("创建告警失败: {}".format(e))
            return {"status": "error", "message": str(e)}

    def _dispatch_alert(self, alert: Alert):
        """
        分发告警到所有配置的通道

        Args:
            alert: 告警对象
        """
        alert_data = {
            "title": alert.title,
            "level": alert.level.value,
            "source": alert.source,
            "description": alert.description or "",
            "source_ip": alert.source_ip or "",
            "dest_ip": alert.dest_ip or "",
            "metadata": alert.metadata_json,
        }

        # 邮件告警（仅高优先级）
        if alert.level in (AlertLevel.HIGH, AlertLevel.CRITICAL):
            try:
                self._email_alerter.send_alert(**alert_data)
                self._stats["email_sent"] += 1
            except Exception as e:
                logger.error("邮件告警发送失败: {}".format(e))

        # Webhook告警
        try:
            self._webhook_alerter.send_alert(**alert_data)
            self._stats["webhook_sent"] += 1
        except Exception as e:
            logger.error("Webhook告警发送失败: {}".format(e))

    def _is_on_cooldown(self, key: str) -> bool:
        """检查是否在冷却期"""
        last_alert_time = self._alert_cooldown.get(key, 0)
        return (time.time() - last_alert_time) < self._cooldown_seconds

    def _check_rate_limit(self) -> bool:
        """检查频率限制"""
        now = time.time()
        minute_key = str(int(now / 60))

        if minute_key not in self._rate_counter:
            # 清理旧的计数器
            old_keys = [k for k in self._rate_counter if k != minute_key]
            for k in old_keys:
                del self._rate_counter[k]
            self._rate_counter[minute_key] = 0

        if self._rate_counter[minute_key] >= self._max_per_minute:
            return False

        self._rate_counter[minute_key] += 1
        return True

    def register_callback(self, callback: Callable):
        """注册告警回调函数"""
        self._callbacks.append(callback)

    def get_statistics(self) -> Dict[str, Any]:
        """获取告警统计"""
        try:
            with db_manager.get_session() as session:
                from sqlalchemy import func
                total = session.query(Alert).count()
                new_count = session.query(Alert).filter_by(status=AlertStatus.NEW).count()
                by_level = (
                    session.query(Alert.level, func.count(Alert.id))
                    .group_by(Alert.level)
                    .all()
                )
        except Exception:
            total = 0
            new_count = 0
            by_level = []

        return {
            **self._stats,
            "total_alerts": total,
            "new_alerts": new_count,
            "by_level": {l.value: c for l, c in by_level},
            "channels": {
                "email": settings.alert.email_enabled,
                "webhook": settings.alert.webhook_enabled,
            },
        }

    def get_alerts(
        self,
        level: Optional[str] = None,
        status: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> List[Dict[str, Any]]:
        """获取告警列表"""
        try:
            with db_manager.get_session() as session:
                query = session.query(Alert)
                if level:
                    query = query.filter(Alert.level == AlertLevel(level))
                if status:
                    query = query.filter(Alert.status == AlertStatus(status))

                alerts = (
                    query.order_by(Alert.created_at.desc())
                    .offset(offset)
                    .limit(limit)
                    .all()
                )

                return [
                    {
                        "id": a.id,
                        "title": a.title,
                        "description": a.description,
                        "level": a.level.value,
                        "status": a.status.value,
                        "source": a.source,
                        "source_ip": a.source_ip,
                        "dest_ip": a.dest_ip,
                        "created_at": a.created_at.isoformat() if a.created_at else None,
                    }
                    for a in alerts
                ]
        except Exception as e:
            logger.error("获取告警列表失败: {}".format(e))
            return []
