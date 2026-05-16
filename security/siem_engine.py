"""
GateKeeper - SIEM引擎 (安全信息和事件管理)
提供多数据源事件聚合、关联分析和攻击链追踪功能
"""

import uuid
import json
import csv
import io
import copy
import threading
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from collections import defaultdict

from config.logging_config import get_logger
from core.database import db_manager
from core.models import (
    AttackLog, AttackType, AttackSeverity,
    AuditLog, Alert, AlertLevel, TrafficLog, FirewallRule,
)

logger = get_logger("siem_engine")


# ============================================================
# SIEM事件
# ============================================================

class SIEMEvent:
    """SIEM统一事件模型"""

    SEVERITY_LEVELS = {
        "info": 0,
        "low": 1,
        "medium": 2,
        "high": 3,
        "critical": 4,
    }

    def __init__(
        self,
        source: str,
        severity: str = "info",
        source_ip: str = "",
        dest_ip: str = "",
        event_type: str = "",
        title: str = "",
        description: str = "",
        raw_data: Optional[Dict] = None,
        tags: Optional[List[str]] = None,
        correlation_id: str = "",
        timestamp: Optional[datetime] = None,
        event_id: Optional[str] = None,
    ):
        self.id = event_id or str(uuid.uuid4())
        self.timestamp = timestamp or datetime.now()
        self.source = source  # attack / audit / alert / traffic / firewall / waf / ddos / honeypot / dns
        self.severity = severity.lower() if severity else "info"
        self.source_ip = source_ip
        self.dest_ip = dest_ip
        self.event_type = event_type
        self.title = title
        self.description = description
        self.raw_data = raw_data or {}
        self.tags = tags or []
        self.correlation_id = correlation_id

    def to_dict(self) -> Dict:
        """序列化为字典"""
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "source": self.source,
            "severity": self.severity,
            "source_ip": self.source_ip,
            "dest_ip": self.dest_ip,
            "event_type": self.event_type,
            "title": self.title,
            "description": self.description,
            "raw_data": self.raw_data,
            "tags": self.tags,
            "correlation_id": self.correlation_id,
        }

    @classmethod
    def from_dict(cls, data: Dict) -> "SIEMEvent":
        """从字典反序列化"""
        evt = cls(
            source=data.get("source", "unknown"),
            severity=data.get("severity", "info"),
            source_ip=data.get("source_ip", ""),
            dest_ip=data.get("dest_ip", ""),
            event_type=data.get("event_type", ""),
            title=data.get("title", ""),
            description=data.get("description", ""),
            raw_data=data.get("raw_data", {}),
            tags=data.get("tags", []),
            correlation_id=data.get("correlation_id", ""),
            event_id=data.get("id"),
        )
        if data.get("timestamp"):
            try:
                evt.timestamp = datetime.fromisoformat(data["timestamp"])
            except (ValueError, TypeError):
                pass
        return evt


# ============================================================
# 关联分析规则
# ============================================================

class SIEMCorrelationRule:
    """SIEM关联分析规则"""

    def __init__(
        self,
        name: str,
        description: str = "",
        conditions: Optional[List[Dict]] = None,
        action: str = "alert",
        severity: str = "high",
        threshold: int = 1,
        enabled: bool = True,
        rule_id: Optional[str] = None,
    ):
        self.id = rule_id or str(uuid.uuid4())
        self.name = name
        self.description = description
        self.conditions = conditions or []
        self.action = action  # alert / log
        self.severity = severity
        self.threshold = threshold
        self.enabled = enabled

    def to_dict(self) -> Dict:
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "conditions": self.conditions,
            "action": self.action,
            "severity": self.severity,
            "threshold": self.threshold,
            "enabled": self.enabled,
        }

    @classmethod
    def from_dict(cls, data: Dict) -> "SIEMCorrelationRule":
        return cls(
            name=data.get("name", ""),
            description=data.get("description", ""),
            conditions=data.get("conditions", []),
            action=data.get("action", "alert"),
            severity=data.get("severity", "high"),
            threshold=data.get("threshold", 1),
            enabled=data.get("enabled", True),
            rule_id=data.get("id"),
        )


# ============================================================
# SIEM引擎
# ============================================================

class SIEMEngine:
    """
    SIEM引擎 - 安全信息和事件管理
    聚合多数据源事件，执行关联分析，追踪攻击链
    """

    def __init__(self):
        # 事件缓存（内存中保存最近的事件用于关联分析）
        self._events: List[SIEMEvent] = []
        self._events_lock = threading.Lock()
        self._max_cache_events = 10000

        # 关联规则
        self._correlation_rules: List[SIEMCorrelationRule] = []
        self._rules_lock = threading.Lock()

        # 关联告警结果
        self._correlation_alerts: List[Dict] = []

        # 初始化内置关联规则
        self._init_builtin_rules()

        logger.info("SIEM引擎初始化完成")

    # ----------------------------------------------------------
    # 内置关联规则
    # ----------------------------------------------------------

    def _init_builtin_rules(self):
        """初始化内置关联分析规则"""
        builtin_rules = [
            SIEMCorrelationRule(
                name="暴力破解后入侵",
                description="同一IP在5分钟内出现超过10次登录失败后紧跟1次登录成功",
                conditions=[
                    {
                        "source": "audit",
                        "event_type": "login_failure",
                        "field": "source_ip",
                        "operator": "same_ip",
                        "timeframe": 300,
                        "min_count": 10,
                    },
                    {
                        "source": "audit",
                        "event_type": "login_success",
                        "field": "source_ip",
                        "operator": "same_ip",
                        "timeframe": 300,
                        "min_count": 1,
                    },
                ],
                action="alert",
                severity="critical",
                threshold=1,
            ),
            SIEMCorrelationRule(
                name="扫描后攻击",
                description="同一IP在10分钟内先进行端口扫描，随后发起漏洞利用",
                conditions=[
                    {
                        "source": "attack",
                        "event_type": "port_scan",
                        "field": "source_ip",
                        "operator": "same_ip",
                        "timeframe": 600,
                        "min_count": 1,
                    },
                    {
                        "source": "attack",
                        "event_type": "exploit",
                        "field": "source_ip",
                        "operator": "same_ip",
                        "timeframe": 600,
                        "min_count": 1,
                    },
                ],
                action="alert",
                severity="critical",
                threshold=1,
            ),
            SIEMCorrelationRule(
                name="DDoS攻击",
                description="同一目标在1分钟内收到来自超过100个不同源IP的SYN包",
                conditions=[
                    {
                        "source": "traffic",
                        "event_type": "syn_flood",
                        "field": "dest_ip",
                        "operator": "unique_src_count",
                        "timeframe": 60,
                        "min_count": 100,
                    },
                ],
                action="alert",
                severity="critical",
                threshold=1,
            ),
            SIEMCorrelationRule(
                name="数据泄露",
                description="IDS检测到SQL注入攻击且目标产生大量数据响应",
                conditions=[
                    {
                        "source": "attack",
                        "event_type": "sql_injection",
                        "field": "source_ip",
                        "operator": "same_ip",
                        "timeframe": 300,
                        "min_count": 1,
                    },
                    {
                        "source": "traffic",
                        "event_type": "large_response",
                        "field": "dest_ip",
                        "operator": "same_ip_as_src",
                        "timeframe": 300,
                        "min_count": 1,
                    },
                ],
                action="alert",
                severity="high",
                threshold=1,
            ),
            SIEMCorrelationRule(
                name="横向移动",
                description="同一源IP在短时间内扫描内网多个不同主机",
                conditions=[
                    {
                        "source": "attack",
                        "event_type": "port_scan",
                        "field": "source_ip",
                        "operator": "unique_dst_count",
                        "timeframe": 600,
                        "min_count": 5,
                    },
                ],
                action="alert",
                severity="high",
                threshold=1,
            ),
        ]
        self._correlation_rules = builtin_rules

    # ----------------------------------------------------------
    # 事件收集
    # ----------------------------------------------------------

    def collect_events(self) -> List[SIEMEvent]:
        """
        从所有数据源收集事件，聚合为SIEM事件格式
        """
        all_events = []

        try:
            all_events.extend(self._collect_attack_events())
        except Exception as e:
            logger.error("收集攻击日志事件失败: {}".format(e))

        try:
            all_events.extend(self._collect_audit_events())
        except Exception as e:
            logger.error("收集操作日志事件失败: {}".format(e))

        try:
            all_events.extend(self._collect_alert_events())
        except Exception as e:
            logger.error("收集告警事件失败: {}".format(e))

        try:
            all_events.extend(self._collect_traffic_events())
        except Exception as e:
            logger.error("收集流量事件失败: {}".format(e))

        try:
            all_events.extend(self._collect_firewall_events())
        except Exception as e:
            logger.error("收集防火墙事件失败: {}".format(e))

        # 按时间倒序排列
        all_events.sort(key=lambda e: e.timestamp, reverse=True)

        # 更新缓存
        with self._events_lock:
            self._events = all_events[:self._max_cache_events]

        logger.debug("SIEM事件收集完成，共 {} 条".format(len(all_events)))
        return all_events

    def _collect_attack_events(self) -> List[SIEMEvent]:
        """从攻击日志收集事件"""
        events = []
        cutoff = datetime.now() - timedelta(hours=24)

        with db_manager.get_session() as session:
            logs = session.query(AttackLog).filter(
                AttackLog.timestamp >= cutoff
            ).order_by(AttackLog.timestamp.desc()).limit(500).all()

            for log in logs:
                severity = "info"
                if log.severity:
                    severity = log.severity.value if hasattr(log.severity, "value") else str(log.severity)

                event_type = "unknown"
                if log.attack_type:
                    event_type = log.attack_type.value if hasattr(log.attack_type, "value") else str(log.attack_type)

                # 标记登录相关事件
                tags = ["ids"]
                if event_type == "brute_force":
                    tags.append("brute_force")
                if event_type == "port_scan":
                    tags.append("scan")
                if event_type == "exploit":
                    tags.append("exploit")
                if event_type == "sql_injection":
                    tags.append("injection")

                events.append(SIEMEvent(
                    source="attack",
                    severity=severity,
                    source_ip=log.src_ip or "",
                    dest_ip=log.dst_ip or "",
                    event_type=event_type,
                    title="IDS检测: {}".format(log.signature or event_type),
                    description=log.description or "",
                    raw_data={
                        "attack_log_id": log.id,
                        "signature": log.signature,
                        "payload_preview": log.payload_preview,
                        "protocol": log.protocol,
                        "dst_port": log.dst_port,
                        "is_blocked": log.is_blocked,
                    },
                    tags=tags,
                    timestamp=log.timestamp,
                ))

        return events

    def _collect_audit_events(self) -> List[SIEMEvent]:
        """从操作日志收集事件"""
        events = []
        cutoff = datetime.now() - timedelta(hours=24)

        with db_manager.get_session() as session:
            logs = session.query(AuditLog).filter(
                AuditLog.timestamp >= cutoff
            ).order_by(AuditLog.timestamp.desc()).limit(500).all()

            for log in logs:
                severity = "info"
                tags = ["audit"]

                # 登录失败标记为medium
                if log.action in ("login", "login_failure") and log.result == "failure":
                    severity = "medium"
                    tags.append("login_failure")
                elif log.action == "login" and log.result == "success":
                    severity = "low"
                    tags.append("login_success")
                elif log.result == "failure":
                    severity = "low"
                    tags.append("operation_failure")

                event_type = log.action or "unknown"

                events.append(SIEMEvent(
                    source="audit",
                    severity=severity,
                    source_ip=log.client_ip or "",
                    dest_ip="",
                    event_type=event_type,
                    title="操作日志: {} - {}".format(log.action or "", log.module or ""),
                    description=log.detail or "",
                    raw_data={
                        "audit_log_id": log.id,
                        "username": log.username,
                        "module": log.module,
                        "action": log.action,
                        "result": log.result,
                        "source_type": log.source,
                    },
                    tags=tags,
                    timestamp=log.timestamp,
                ))

        return events

    def _collect_alert_events(self) -> List[SIEMEvent]:
        """从告警收集事件"""
        events = []
        cutoff = datetime.now() - timedelta(hours=24)

        with db_manager.get_session() as session:
            alerts = session.query(Alert).filter(
                Alert.created_at >= cutoff
            ).order_by(Alert.created_at.desc()).limit(200).all()

            for alert in alerts:
                severity = "info"
                if alert.level:
                    severity = alert.level.value if hasattr(alert.level, "value") else str(alert.level)

                events.append(SIEMEvent(
                    source="alert",
                    severity=severity,
                    source_ip=alert.source_ip or "",
                    dest_ip=alert.dest_ip or "",
                    event_type=alert.source or "unknown",
                    title="告警: {}".format(alert.title or ""),
                    description=alert.description or "",
                    raw_data={
                        "alert_id": alert.id,
                        "status": alert.status.value if hasattr(alert.status, "value") else str(alert.status),
                        "source": alert.source,
                        "port": alert.port,
                        "protocol": alert.protocol,
                        "severity_score": alert.severity_score,
                    },
                    tags=["alert", alert.source or ""],
                    timestamp=alert.created_at,
                ))

        return events

    def _collect_traffic_events(self) -> List[SIEMEvent]:
        """从流量日志收集事件（仅异常流量）"""
        events = []
        cutoff = datetime.now() - timedelta(hours=24)

        with db_manager.get_session() as session:
            logs = session.query(TrafficLog).filter(
                TrafficLog.timestamp >= cutoff,
                TrafficLog.is_anomaly == True,
            ).order_by(TrafficLog.timestamp.desc()).limit(500).all()

            for log in logs:
                severity = "medium"
                if log.anomaly_score and log.anomaly_score >= 0.8:
                    severity = "high"
                elif log.anomaly_score and log.anomaly_score >= 0.9:
                    severity = "critical"

                event_type = "anomaly"
                tags = ["traffic", "anomaly"]

                # 根据威胁标签分类
                if log.threat_label:
                    tags.append(log.threat_label)
                    event_type = log.threat_label.lower().replace(" ", "_")

                # 检测SYN洪水
                if log.flags and "SYN" in str(log.flags).upper() and "ACK" not in str(log.flags).upper():
                    tags.append("syn")
                    event_type = "syn_flood"

                # 检测大包响应
                if log.packet_length and log.packet_length > 10000:
                    tags.append("large_response")
                    event_type = "large_response"

                events.append(SIEMEvent(
                    source="traffic",
                    severity=severity,
                    source_ip=log.source_ip or "",
                    dest_ip=log.dest_ip or "",
                    event_type=event_type,
                    title="异常流量: {} -> {}".format(log.source_ip, log.dest_ip),
                    description="威胁标签: {}, 异常分数: {}".format(
                        log.threat_label or "未知", log.anomaly_score or 0
                    ),
                    raw_data={
                        "traffic_log_id": log.id,
                        "protocol": log.protocol,
                        "src_port": None,
                        "dst_port": log.dest_port,
                        "packet_length": log.packet_length,
                        "flags": log.flags,
                        "anomaly_score": log.anomaly_score,
                        "threat_label": log.threat_label,
                    },
                    tags=tags,
                    timestamp=log.timestamp,
                ))

        return events

    def _collect_firewall_events(self) -> List[SIEMEvent]:
        """从防火墙规则收集事件（高命中规则）"""
        events = []

        with db_manager.get_session() as session:
            rules = session.query(FirewallRule).filter(
                FirewallRule.hit_count > 0,
                FirewallRule.is_enabled == True,
            ).order_by(FirewallRule.hit_count.desc()).limit(50).all()

            for rule in rules:
                severity = "info"
                tags = ["firewall"]
                if rule.action and hasattr(rule.action, "value"):
                    action_val = rule.action.value
                    if action_val == "drop":
                        severity = "medium"
                        tags.append("dropped")
                    elif action_val == "reject":
                        severity = "low"
                        tags.append("rejected")
                    elif action_val == "accept":
                        tags.append("accepted")

                events.append(SIEMEvent(
                    source="firewall",
                    severity=severity,
                    source_ip=rule.source_ip or "",
                    dest_ip=rule.dest_ip or "",
                    event_type="firewall_rule",
                    title="防火墙规则: {} (命中 {} 次)".format(rule.name, rule.hit_count),
                    description=rule.description or "",
                    raw_data={
                        "firewall_rule_id": rule.id,
                        "name": rule.name,
                        "chain": rule.chain,
                        "protocol": rule.protocol.value if hasattr(rule.protocol, "value") else str(rule.protocol),
                        "action": action_val if rule.action and hasattr(rule.action, "value") else str(rule.action),
                        "hit_count": rule.hit_count,
                        "priority": rule.priority,
                    },
                    tags=tags,
                    timestamp=rule.updated_at or rule.created_at,
                ))

        return events

    # ----------------------------------------------------------
    # 关联分析
    # ----------------------------------------------------------

    def correlate_events(self) -> List[Dict]:
        """
        对缓存的事件执行关联分析
        返回触发的关联告警列表
        """
        alerts = []

        with self._events_lock:
            events_snapshot = list(self._events)

        with self._rules_lock:
            rules_snapshot = list(self._correlation_rules)

        for rule in rules_snapshot:
            if not rule.enabled:
                continue
            try:
                matched = self._evaluate_rule(rule, events_snapshot)
                if matched:
                    alerts.append(matched)
            except Exception as e:
                logger.error("关联规则 '{}' 执行失败: {}".format(rule.name, e))

        self._correlation_alerts = alerts
        logger.info("关联分析完成，触发 {} 条关联告警".format(len(alerts)))
        return alerts

    def _evaluate_rule(self, rule: SIEMCorrelationRule, events: List[SIEMEvent]) -> Optional[Dict]:
        """
        评估单条关联规则
        """
        if not rule.conditions:
            return None

        now = datetime.now()
        # 计算规则的时间窗口（取所有条件中最大的timeframe）
        max_timeframe = max(c.get("timeframe", 300) for c in rule.conditions)
        window_start = now - timedelta(seconds=max_timeframe)

        # 过滤时间窗口内的事件
        window_events = [e for e in events if e.timestamp and e.timestamp >= window_start]
        if not window_events:
            return None

        # 按条件匹配事件组
        condition_groups = []
        for cond in rule.conditions:
            matched_events = self._match_condition(cond, window_events)
            condition_groups.append(matched_events)

        # 所有条件都必须匹配
        for group in condition_groups:
            if not group:
                return None

        # 生成关联告警
        correlation_id = str(uuid.uuid4())
        all_matched_events = []
        for group in condition_groups:
            all_matched_events.extend(group)

        # 提取关键IP
        source_ips = list(set(e.source_ip for e in all_matched_events if e.source_ip))
        dest_ips = list(set(e.dest_ip for e in all_matched_events if e.dest_ip))

        alert = {
            "id": correlation_id,
            "rule_name": rule.name,
            "rule_id": rule.id,
            "description": rule.description,
            "severity": rule.severity,
            "action": rule.action,
            "timestamp": now.isoformat(),
            "source_ips": source_ips,
            "dest_ips": dest_ips,
            "event_count": len(all_matched_events),
            "events": [e.to_dict() for e in all_matched_events[:20]],  # 最多保留20条事件
            "tags": ["correlation", rule.name],
        }

        # 为匹配到的事件打上关联ID
        for evt in all_matched_events:
            evt.correlation_id = correlation_id

        logger.warning(
            "关联告警触发: '{}' - 涉及 {} 个事件, 来源IP: {}".format(
                rule.name, len(all_matched_events), ", ".join(source_ips[:5])
            )
        )

        return alert

    def _match_condition(self, condition: Dict, events: List[SIEMEvent]) -> List[SIEMEvent]:
        """
        根据单个条件匹配事件
        """
        source = condition.get("source", "")
        event_type = condition.get("event_type", "")
        field = condition.get("field", "")
        operator = condition.get("operator", "eq")
        value = condition.get("value", "")
        timeframe = condition.get("timeframe", 300)
        min_count = condition.get("min_count", 1)

        # 基础过滤：按来源和事件类型
        matched = []
        for evt in events:
            if source and evt.source != source:
                continue
            if event_type and evt.event_type != event_type:
                continue
            matched.append(evt)

        if not matched:
            return []

        now = datetime.now()
        window_start = now - timedelta(seconds=timeframe)
        matched = [e for e in matched if e.timestamp and e.timestamp >= window_start]

        if not matched:
            return []

        # 根据操作符进行高级匹配
        if operator == "same_ip":
            # 找出出现次数 >= min_count 的IP
            ip_counts = defaultdict(list)
            for e in matched:
                ip = getattr(e, field, "") or ""
                if ip:
                    ip_counts[ip].append(e)
            result = []
            for ip, evts in ip_counts.items():
                if len(evts) >= min_count:
                    result.extend(evts)
            return result

        elif operator == "unique_src_count":
            # 同一目标IP的不同源IP数量 >= min_count
            dst_groups = defaultdict(set)
            for e in matched:
                dst = getattr(e, field, "") or ""
                if dst:
                    dst_groups[dst].add(e.source_ip)
            result = []
            for dst, src_ips in dst_groups.items():
                if len(src_ips) >= min_count:
                    result.extend([e for e in matched if (getattr(e, field, "") or "") == dst])
            return result

        elif operator == "unique_dst_count":
            # 同一源IP的不同目标IP数量 >= min_count
            src_groups = defaultdict(set)
            for e in matched:
                src = getattr(e, field, "") or ""
                if src:
                    src_groups[src].add(e.dest_ip)
            result = []
            for src, dst_ips in src_groups.items():
                if len(dst_ips) >= min_count:
                    result.extend([e for e in matched if (getattr(e, field, "") or "") == src])
            return result

        elif operator == "same_ip_as_src":
            # source_ip == 另一组事件的dest_ip
            return matched if len(matched) >= min_count else []

        elif operator == "eq":
            field_val = value
            result = [e for e in matched if getattr(e, field, "") == field_val]
            return result if len(result) >= min_count else []

        elif operator == "ne":
            field_val = value
            result = [e for e in matched if getattr(e, field, "") != field_val]
            return result if len(result) >= min_count else []

        elif operator == "gt":
            try:
                field_val = float(value)
                result = [e for e in matched if float(getattr(e, field, 0) or 0) > field_val]
                return result if len(result) >= min_count else []
            except (ValueError, TypeError):
                return []

        elif operator == "lt":
            try:
                field_val = float(value)
                result = [e for e in matched if float(getattr(e, field, 0) or 0) < field_val]
                return result if len(result) >= min_count else []
            except (ValueError, TypeError):
                return []

        elif operator == "contains":
            field_val = value
            result = [e for e in matched if field_val in str(getattr(e, field, ""))]
            return result if len(result) >= min_count else []

        # 默认返回所有匹配（只要满足min_count）
        return matched if len(matched) >= min_count else []

    # ----------------------------------------------------------
    # 事件查询
    # ----------------------------------------------------------

    def get_events(
        self,
        source: Optional[str] = None,
        severity: Optional[str] = None,
        keyword: Optional[str] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        page: int = 1,
        page_size: int = 50,
    ) -> Dict:
        """
        查询SIEM事件（分页）
        """
        # 确保缓存中有数据
        if not self._events:
            self.collect_events()

        with self._events_lock:
            events = list(self._events)

        # 过滤
        if source:
            events = [e for e in events if e.source == source]
        if severity:
            events = [e for e in events if e.severity == severity.lower()]
        if keyword:
            kw = keyword.lower()
            events = [e for e in events if kw in e.title.lower() or kw in e.description.lower()
                      or kw in e.source_ip or kw in e.dest_ip or kw in str(e.tags)]
        if start_time:
            events = [e for e in events if e.timestamp and e.timestamp >= start_time]
        if end_time:
            events = [e for e in events if e.timestamp and e.timestamp <= end_time]

        total = len(events)
        total_pages = (total + page_size - 1) // page_size if total > 0 else 1
        start_idx = (page - 1) * page_size
        end_idx = start_idx + page_size
        page_events = events[start_idx:end_idx]

        return {
            "total": total,
            "page": page,
            "page_size": page_size,
            "total_pages": total_pages,
            "events": [e.to_dict() for e in page_events],
        }

    # ----------------------------------------------------------
    # 统计
    # ----------------------------------------------------------

    def get_stats(self) -> Dict:
        """获取SIEM统计信息"""
        # 确保缓存中有数据
        if not self._events:
            self.collect_events()

        with self._events_lock:
            events = list(self._events)

        now = datetime.now()
        today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)

        total_events = len(events)
        today_events = len([e for e in events if e.timestamp and e.timestamp >= today_start])

        # 按来源统计
        source_stats = defaultdict(int)
        for e in events:
            source_stats[e.source] += 1

        # 按严重度统计
        severity_stats = defaultdict(int)
        for e in events:
            severity_stats[e.severity] += 1

        # 高危事件数
        high_severity_events = len([
            e for e in events if e.severity in ("high", "critical")
        ])

        # 关联告警数
        correlation_count = len(self._correlation_alerts)

        return {
            "total_events": total_events,
            "today_events": today_events,
            "high_severity_events": high_severity_events,
            "correlation_alerts": correlation_count,
            "by_source": dict(source_stats),
            "by_severity": dict(severity_stats),
        }

    # ----------------------------------------------------------
    # 时间线
    # ----------------------------------------------------------

    def get_timeline(self, hours: int = 24) -> Dict:
        """
        获取事件时间线数据（按小时分桶，按严重度分层）
        """
        if not self._events:
            self.collect_events()

        with self._events_lock:
            events = list(self._events)

        now = datetime.now()
        window_start = now - timedelta(hours=hours)

        # 按小时分桶
        buckets = {}
        for i in range(hours):
            bucket_time = window_start + timedelta(hours=i)
            bucket_key = bucket_time.strftime("%Y-%m-%d %H:00")
            buckets[bucket_key] = {
                "info": 0,
                "low": 0,
                "medium": 0,
                "high": 0,
                "critical": 0,
            }

        for evt in events:
            if evt.timestamp and evt.timestamp >= window_start:
                bucket_key = evt.timestamp.strftime("%Y-%m-%d %H:00")
                if bucket_key in buckets:
                    sev = evt.severity
                    if sev in buckets[bucket_key]:
                        buckets[bucket_key][sev] += 1

        labels = list(buckets.keys())
        timeline_data = {
            "labels": labels,
            "info": [buckets[l]["info"] for l in labels],
            "low": [buckets[l]["low"] for l in labels],
            "medium": [buckets[l]["medium"] for l in labels],
            "high": [buckets[l]["high"] for l in labels],
            "critical": [buckets[l]["critical"] for l in labels],
        }

        return timeline_data

    # ----------------------------------------------------------
    # 攻击链
    # ----------------------------------------------------------

    def get_attack_chain(self, ip: str) -> Dict:
        """
        获取指定IP的攻击链（关联事件序列）
        """
        if not self._events:
            self.collect_events()

        with self._events_lock:
            events = list(self._events)

        ip = ip.strip()
        ip_lower = ip.lower()

        # 找出与该IP相关的所有事件（源IP或目标IP匹配）
        related_events = [
            e for e in events
            if (e.source_ip and e.source_ip.lower() == ip_lower)
            or (e.dest_ip and e.dest_ip.lower() == ip_lower)
        ]

        # 按时间排序
        related_events.sort(key=lambda e: e.timestamp or datetime.min)

        # 构建攻击链阶段
        chain_stages = []
        seen_types = set()

        for evt in related_events:
            stage = self._classify_event_stage(evt)
            if stage not in seen_types:
                seen_types.add(stage)
                chain_stages.append({
                    "stage": stage,
                    "timestamp": evt.timestamp.isoformat() if evt.timestamp else None,
                    "event_type": evt.event_type,
                    "title": evt.title,
                    "severity": evt.severity,
                    "source": evt.source,
                })

        # 统计
        severity_counts = defaultdict(int)
        source_counts = defaultdict(int)
        type_counts = defaultdict(int)
        for evt in related_events:
            severity_counts[evt.severity] += 1
            source_counts[evt.source] += 1
            type_counts[evt.event_type] += 1

        return {
            "ip": ip,
            "total_events": len(related_events),
            "chain_stages": chain_stages,
            "events": [e.to_dict() for e in related_events[:100]],
            "by_severity": dict(severity_counts),
            "by_source": dict(source_counts),
            "by_type": dict(type_counts),
            "risk_level": self._assess_ip_risk(related_events),
        }

    def _classify_event_stage(self, event: SIEMEvent) -> str:
        """将事件分类到攻击链阶段"""
        if event.source == "attack":
            if event.event_type == "port_scan":
                return "侦察扫描"
            elif event.event_type == "brute_force":
                return "暴力破解"
            elif event.event_type in ("exploit", "sql_injection", "command_injection", "xss"):
                return "漏洞利用"
            elif event.event_type == "malicious_tool":
                return "工具检测"
            else:
                return "攻击行为"
        elif event.source == "audit":
            if "login_failure" in event.tags:
                return "登录尝试"
            elif "login_success" in event.tags:
                return "入侵成功"
            else:
                return "操作记录"
        elif event.source == "traffic":
            if event.event_type == "syn_flood":
                return "DDoS攻击"
            elif "anomaly" in event.tags:
                return "异常流量"
            else:
                return "流量事件"
        elif event.source == "alert":
            return "告警事件"
        elif event.source == "firewall":
            if "dropped" in event.tags:
                return "防火墙阻断"
            else:
                return "防火墙事件"
        else:
            return "其他事件"

    def _assess_ip_risk(self, events: List[SIEMEvent]) -> str:
        """评估IP的风险等级"""
        if not events:
            return "unknown"

        severity_scores = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
        max_score = 0
        total_score = 0

        for e in events:
            score = severity_scores.get(e.severity, 0)
            total_score += score
            if score > max_score:
                max_score = score

        avg_score = total_score / len(events)

        if max_score >= 4 or avg_score >= 3:
            return "critical"
        elif max_score >= 3 or avg_score >= 2:
            return "high"
        elif max_score >= 2 or avg_score >= 1:
            return "medium"
        elif total_score > 0:
            return "low"
        return "info"

    # ----------------------------------------------------------
    # 关联规则管理
    # ----------------------------------------------------------

    def add_correlation_rule(self, rule: SIEMCorrelationRule) -> SIEMCorrelationRule:
        """添加关联规则"""
        with self._rules_lock:
            self._correlation_rules.append(rule)
        logger.info("添加关联规则: '{}'".format(rule.name))
        return rule

    def remove_correlation_rule(self, rule_id: str) -> bool:
        """删除关联规则"""
        with self._rules_lock:
            original_len = len(self._correlation_rules)
            self._correlation_rules = [
                r for r in self._correlation_rules if r.id != rule_id
            ]
            removed = len(self._correlation_rules) < original_len
        if removed:
            logger.info("删除关联规则: {}".format(rule_id))
        return removed

    def get_correlation_rules(self) -> List[Dict]:
        """获取所有关联规则"""
        with self._rules_lock:
            return [r.to_dict() for r in self._correlation_rules]

    def get_correlation_alerts(self) -> List[Dict]:
        """获取最近的关联告警"""
        return self._correlation_alerts

    # ----------------------------------------------------------
    # 导出
    # ----------------------------------------------------------

    def export_events(self, format: str = "json") -> str:
        """导出SIEM事件"""
        if not self._events:
            self.collect_events()

        with self._events_lock:
            events = list(self._events)

        if format == "json":
            return json.dumps(
                [e.to_dict() for e in events],
                ensure_ascii=False,
                indent=2,
            )
        elif format == "csv":
            output = io.StringIO()
            writer = csv.writer(output)
            writer.writerow([
                "ID", "时间", "来源", "严重度", "源IP", "目标IP",
                "事件类型", "标题", "描述", "标签", "关联ID"
            ])
            for e in events:
                writer.writerow([
                    e.id,
                    e.timestamp.isoformat() if e.timestamp else "",
                    e.source,
                    e.severity,
                    e.source_ip,
                    e.dest_ip,
                    e.event_type,
                    e.title,
                    e.description,
                    "|".join(e.tags),
                    e.correlation_id,
                ])
            return output.getvalue()
        else:
            return ""


# ============================================================
# 单例
# ============================================================

_siem_engine: Optional[SIEMEngine] = None
_siem_engine_lock = threading.Lock()


def get_siem_engine() -> SIEMEngine:
    """获取SIEM引擎单例"""
    global _siem_engine
    if _siem_engine is None:
        with _siem_engine_lock:
            if _siem_engine is None:
                _siem_engine = SIEMEngine()
    return _siem_engine
