"""
GateKeeper - SSE (Server-Sent Events) 实时推送
使用 Server-Sent Events 实现服务端向客户端的实时消息推送
"""

import json
import queue
import time
import threading
from datetime import datetime

from flask import Blueprint, Response, request
from flask_login import login_required

from config.logging_config import get_logger

logger = get_logger("sse")

ws_bp = Blueprint("ws", __name__)


class EventBus:
    """
    事件总线，使用发布-订阅模式实现线程安全的事件广播
    每个订阅者拥有独立的 queue.Queue，publish() 会将事件推送到所有订阅者队列
    """

    MAX_SUBSCRIBERS = 1000

    def __init__(self):
        self._subscribers = {}  # id -> queue.Queue
        self._next_sub_id = 0
        self._lock = threading.Lock()

    def subscribe(self) -> int:
        """
        创建一个新的订阅者，返回订阅者ID

        Returns:
            订阅者ID（整数）
        """
        with self._lock:
            if len(self._subscribers) >= self.MAX_SUBSCRIBERS:
                raise Exception("SSE 订阅者数量已达上限")
            q = queue.Queue(maxsize=5000)
            sub_id = self._next_sub_id
            self._next_sub_id += 1
            self._subscribers[sub_id] = q
        return sub_id

    def unsubscribe(self, sub_id: int):
        """
        移除订阅者

        Args:
            sub_id: 订阅者ID
        """
        with self._lock:
            self._subscribers.pop(sub_id, None)

    def get_event(self, sub_id: int, timeout: float = 30.0) -> dict:
        """
        从指定订阅者的队列中获取一个事件（阻塞等待）

        Args:
            sub_id: 订阅者ID
            timeout: 最大等待时间（秒）

        Returns:
            事件字典，超时返回 None
        """
        q = self._subscribers.get(sub_id)
        if q is None:
            return None
        try:
            return q.get(timeout=timeout)
        except queue.Empty:
            return None

    def publish(self, event_type: str, data: dict = None):
        """
        发布事件到所有订阅者队列

        Args:
            event_type: 事件类型，如 'alert', 'status', 'heartbeat'
            data: 事件数据字典
        """
        event = {
            "type": event_type,
            "data": data or {},
            "timestamp": datetime.now().isoformat(),
        }
        with self._lock:
            for sub_id, q in list(self._subscribers.items()):
                try:
                    q.put_nowait(event)
                except queue.Full:
                    logger.warning("订阅者 {} 队列已满，丢弃事件: type={}".format(sub_id, event_type))

    @property
    def subscribers_count(self) -> int:
        with self._lock:
            return len(self._subscribers)


# 全局事件总线实例
event_bus = EventBus()


def generate_sse_stream():
    """
    SSE 流生成器
    持续从事件总线读取事件并推送给客户端
    包含心跳机制：30秒无事件时发送心跳
    """
    logger.info("新SSE客户端连接")
    sub_id = event_bus.subscribe()

    try:
        while True:
            event = event_bus.get_event(sub_id, timeout=30.0)

            if event is None:
                # 超时无事件，发送心跳
                yield "event: heartbeat\ndata: {\"time\": \"" + datetime.now().isoformat() + "\"}\n\n"
            else:
                event_type = event.get("type", "message")
                event_data = json.dumps(event, ensure_ascii=False, default=str)
                yield "event: {}\ndata: {}\n\n".format(event_type, event_data)

                # 告警事件同时记录日志
                if event_type == "alert":
                    alert_data = event.get("data", {})
                    logger.info("SSE推送告警: level={}, title={}".format(
                        alert_data.get("level", "?"),
                        alert_data.get("title", "?")
                    ))
    except GeneratorExit:
        logger.info("SSE客户端断开连接")
    except Exception as e:
        logger.error("SSE流异常: {}".format(e))
    finally:
        event_bus.unsubscribe(sub_id)


@ws_bp.route("/events")
@login_required
def sse_stream():
    """
    SSE 端点
    客户端通过 EventSource('/events') 连接此端点接收实时事件
    """
    # 检查客户端是否接受 text/event-stream
    accepts = request.headers.get("Accept", "")
    if "text/event-stream" not in accepts:
        return Response(
            json.dumps({"status": "error", "message": "需要 Accept: text/event-stream"}),
            content_type="application/json",
            status=406,
        )

    response = Response(
        generate_sse_stream(),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",  # 禁用 Nginx 缓冲
        },
    )
    return response


def publish_alert(alert_obj):
    """
    发布告警事件到SSE事件总线
    此函数设计为 AlertManager 的回调函数

    Args:
        alert_obj: Alert 模型实例
    """
    event_data = {
        "id": getattr(alert_obj, "id", None),
        "title": getattr(alert_obj, "title", ""),
        "level": getattr(alert_obj, "level", None),
        "level_value": alert_obj.level.value if hasattr(alert_obj, "level") and hasattr(alert_obj.level, "value") else str(getattr(alert_obj, "level", "")),
        "source": getattr(alert_obj, "source", ""),
        "description": getattr(alert_obj, "description", ""),
        "source_ip": getattr(alert_obj, "source_ip", ""),
        "dest_ip": getattr(alert_obj, "dest_ip", ""),
        "created_at": alert_obj.created_at.isoformat() if hasattr(alert_obj, "created_at") and alert_obj.created_at else None,
    }
    event_bus.publish("alert", event_data)


def publish_status(status: str, message: str = ""):
    """
    发布系统状态变更事件

    Args:
        status: 状态标识 (如 'online', 'offline', 'warning')
        message: 状态描述
    """
    event_bus.publish("status", {"status": status, "message": message})
