"""
GateKeeper - IDS优化引擎
基于机器学习的入侵检测系统规则优化，自动调整检测规则以提高准确率
"""

import re
import threading
from typing import Dict, List, Optional, Tuple, Any
from datetime import datetime, timedelta
from collections import defaultdict

try:
    import numpy as np
except ImportError:
    np = None

from config.settings import settings
from config.logging_config import get_logger
from core.database import db_manager
from core.models import IDSRule, Alert, TrafficLog

logger = get_logger("ids_optimizer")


class IDSOptimizer:
    """
    IDS规则优化引擎
    分析告警数据，优化IDS规则，减少误报和漏报
    """

    def __init__(self):
        self._lock = threading.Lock()

        # 规则性能统计
        self._rule_stats: Dict[int, Dict] = {}

        # 误报模式
        self._false_positive_patterns: Dict[str, int] = defaultdict(int)

        # 规则优化历史
        self._optimization_history: List[Dict] = []

        # 性能指标
        self._metrics = {
            "total_rules": 0,
            "active_rules": 0,
            "avg_confidence": 0.0,
            "optimization_count": 0,
            "last_optimization": None,
        }

        logger.info("IDS优化引擎初始化完成")

    def evaluate_rules(self) -> Dict[str, Any]:
        """
        评估当前所有IDS规则的效能
        基于历史告警数据分析每条规则的准确率

        Returns:
            评估结果
        """
        logger.info("开始评估IDS规则...")

        try:
            with db_manager.get_session() as session:
                rules = session.query(IDSRule).filter_by(is_enabled=True).all()
                alerts = (
                    session.query(Alert)
                    .filter(Alert.source == "ids")
                    .filter(Alert.created_at >= datetime.now() - timedelta(days=7))
                    .all()
                )
        except Exception as e:
            logger.error("获取规则和告警数据失败: {}".format(e))
            return {"status": "error", "message": str(e)}

        if not rules:
            return {"status": "no_rules", "message": "无活跃的IDS规则"}

        # 统计每条规则的命中情况
        rule_hit_counts = defaultdict(int)
        rule_alert_counts = defaultdict(int)
        rule_resolved_counts = defaultdict(int)
        rule_ignored_counts = defaultdict(int)

        for alert in alerts:
            if alert.metadata_json and "rule_id" in alert.metadata_json:
                rule_id = alert.metadata_json["rule_id"]
                rule_alert_counts[rule_id] += 1
                if alert.status == "resolved":
                    rule_resolved_counts[rule_id] += 1
                elif alert.status == "ignored":
                    rule_ignored_counts[rule_id] += 1

        # 评估每条规则
        rule_evaluations = []
        for rule in rules:
            total_alerts = rule_alert_counts.get(rule.id, 0)
            resolved = rule_resolved_counts.get(rule.id, 0)
            ignored = rule_ignored_counts.get(rule.id, 0)

            # 计算指标
            precision = resolved / max(total_alerts, 1)
            false_positive_rate = ignored / max(total_alerts, 1)
            effectiveness = precision * rule.confidence

            evaluation = {
                "rule_id": rule.rule_id,
                "name": rule.name,
                "total_alerts": total_alerts,
                "true_positives": resolved,
                "false_positives": ignored,
                "precision": round(precision, 4),
                "false_positive_rate": round(false_positive_rate, 4),
                "effectiveness": round(effectiveness, 4),
                "current_confidence": rule.confidence,
                "hit_count": rule.hit_count,
            }

            rule_evaluations.append(evaluation)

            # 更新内部统计
            self._rule_stats[rule.id] = evaluation

        # 总体统计
        total_alerts = sum(e["total_alerts"] for e in rule_evaluations)
        total_tp = sum(e["true_positives"] for e in rule_evaluations)
        total_fp = sum(e["false_positives"] for e in rule_evaluations)

        overall_precision = total_tp / max(total_alerts, 1)
        overall_fpr = total_fp / max(total_alerts, 1)

        result = {
            "status": "ok",
            "timestamp": datetime.now().isoformat(),
            "total_rules": len(rules),
            "rules_with_alerts": len(rule_alert_counts),
            "total_alerts": total_alerts,
            "overall_precision": round(overall_precision, 4),
            "overall_false_positive_rate": round(overall_fpr, 4),
            "rule_evaluations": sorted(
                rule_evaluations,
                key=lambda x: x["effectiveness"],
                reverse=True,
            ),
        }

        # 更新性能指标
        self._metrics["total_rules"] = len(rules)
        self._metrics["active_rules"] = len([r for r in rules if r.is_enabled])
        self._metrics["avg_confidence"] = round(
            np.mean([r.confidence for r in rules]), 4
        ) if rules else 0.0

        logger.info(
            "IDS规则评估完成: {}条规则, 总体精确率={:.4f}".format(
                len(rules), overall_precision
            )
        )

        return result

    def optimize_rules(self) -> Dict[str, Any]:
        """
        自动优化IDS规则
        基于评估结果调整规则置信度和优先级

        Returns:
            优化结果
        """
        logger.info("开始优化IDS规则...")

        # 先评估
        evaluation = self.evaluate_rules()
        if evaluation.get("status") != "ok":
            return evaluation

        rule_evaluations = evaluation["rule_evaluations"]
        optimizations = []

        for rule_eval in rule_evaluations:
            rule_id = rule_eval["rule_id"]
            fpr = rule_eval["false_positive_rate"]
            precision = rule_eval["precision"]
            current_confidence = rule_eval["current_confidence"]

            changes = {}

            # 规则1: 高误报率 -> 降低置信度
            if fpr > 0.7 and current_confidence > 0.3:
                new_confidence = max(0.1, current_confidence * 0.7)
                changes["confidence"] = {
                    "old": current_confidence,
                    "new": round(new_confidence, 2),
                    "reason": "high_false_positive_rate",
                }

            # 规则2: 高精确率 -> 提升置信度
            elif precision > 0.8 and current_confidence < 0.95:
                new_confidence = min(0.99, current_confidence * 1.1)
                changes["confidence"] = {
                    "old": current_confidence,
                    "new": round(new_confidence, 2),
                    "reason": "high_precision",
                }

            # 规则3: 无命中且长期未使用 -> 建议禁用
            if rule_eval["total_alerts"] == 0 and rule_eval["hit_count"] == 0:
                changes["suggestion"] = "consider_disabling"

            if changes:
                changes["rule_id"] = rule_id
                changes["rule_name"] = rule_eval["name"]
                optimizations.append(changes)

                # 应用置信度变更
                if "confidence" in changes:
                    try:
                        with db_manager.get_session() as session:
                            rule = (
                                session.query(IDSRule)
                                .filter_by(rule_id=rule_id)
                                .first()
                            )
                            if rule:
                                rule.confidence = changes["confidence"]["new"]
                                logger.info(
                                    "更新规则 {} 置信度: {} -> {}".format(
                                        rule_id,
                                        changes['confidence']['old'],
                                        changes['confidence']['new']
                                    )
                                )
                    except Exception as e:
                        logger.error("更新规则 {} 失败: {}".format(rule_id, e))

        # 记录优化历史
        optimization_record = {
            "timestamp": datetime.now().isoformat(),
            "rules_evaluated": len(rule_evaluations),
            "rules_optimized": len(optimizations),
            "optimizations": optimizations,
        }
        self._optimization_history.append(optimization_record)
        self._metrics["optimization_count"] += 1
        self._metrics["last_optimization"] = datetime.now().isoformat()

        result = {
            "status": "ok",
            "timestamp": datetime.now().isoformat(),
            "rules_evaluated": len(rule_evaluations),
            "rules_optimized": len(optimizations),
            "optimizations": optimizations,
        }

        logger.info(
            "IDS规则优化完成: 评估{}条, 优化{}条".format(
                len(rule_evaluations), len(optimizations)
            )
        )

        return result

    def add_rule(
        self,
        rule_id: str,
        name: str,
        pattern: str,
        category: str = "custom",
        protocol: str = "any",
        confidence: float = 0.8,
        description: str = "",
    ) -> Dict[str, Any]:
        """
        添加新的IDS规则

        Args:
            rule_id: 规则唯一标识
            name: 规则名称
            pattern: 匹配模式
            category: 规则分类
            protocol: 协议类型
            confidence: 置信度
            description: 规则描述

        Returns:
            添加结果
        """
        try:
            rule = IDSRule(
                rule_id=rule_id,
                name=name,
                description=description,
                category=category,
                protocol=protocol,
                pattern=pattern,
                confidence=confidence,
                is_enabled=True,
            )
            db_manager.add(rule)

            logger.info("添加IDS规则: {} - {}".format(rule_id, name))
            return {"status": "ok", "rule_id": rule_id}

        except Exception as e:
            logger.error("添加IDS规则失败: {}".format(e))
            return {"status": "error", "message": str(e)}

    def remove_rule(self, rule_id: str) -> Dict[str, Any]:
        """移除IDS规则"""
        try:
            with db_manager.get_session() as session:
                rule = session.query(IDSRule).filter_by(rule_id=rule_id).first()
                if rule:
                    session.delete(rule)
                    logger.info("移除IDS规则: {}".format(rule_id))
                    return {"status": "ok", "rule_id": rule_id}
                return {"status": "not_found", "rule_id": rule_id}
        except Exception as e:
            logger.error("移除IDS规则失败: {}".format(e))
            return {"status": "error", "message": str(e)}

    def match_traffic(self, packet_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        将流量数据与IDS规则进行匹配

        Args:
            packet_data: 数据包信息字典

        Returns:
            匹配的规则列表
        """
        matched_rules = []

        try:
            with db_manager.get_session() as session:
                rules = session.query(IDSRule).filter_by(is_enabled=True).all()

            for rule in rules:
                match_result = self._match_rule(rule, packet_data)
                if match_result["matched"]:
                    matched_rules.append({
                        "rule_id": rule.rule_id,
                        "name": rule.name,
                        "confidence": rule.confidence,
                        "match_details": match_result["details"],
                    })

                    # 更新命中计数
                    try:
                        with db_manager.get_session() as session:
                            r = session.query(IDSRule).filter_by(
                                rule_id=rule.rule_id
                            ).first()
                            if r:
                                r.hit_count += 1
                                r.last_hit = datetime.now()
                    except Exception:
                        pass

        except Exception as e:
            logger.error("规则匹配失败: {}".format(e))

        return matched_rules

    def _match_rule(self, rule: IDSRule, packet_data: Dict) -> Dict[str, Any]:
        """
        将单条规则与数据包匹配

        Args:
            rule: IDS规则
            packet_data: 数据包数据

        Returns:
            匹配结果
        """
        # 协议匹配
        if rule.protocol and rule.protocol.lower() != "any":
            if packet_data.get("protocol", "").upper() != rule.protocol.upper():
                return {"matched": False, "details": {}}

        # 源IP匹配
        if rule.source_ip:
            if packet_data.get("src_ip") != rule.source_ip:
                return {"matched": False, "details": {}}

        # 目标IP匹配
        if rule.dest_ip:
            if packet_data.get("dst_ip") != rule.dest_ip:
                return {"matched": False, "details": {}}

        # 目标端口匹配
        if rule.dest_port:
            pkt_port = packet_data.get("dst_port")
            if pkt_port is None:
                return {"matched": False, "details": {}}
            rule_ports = self._parse_port_range(rule.dest_port)
            if pkt_port not in rule_ports:
                return {"matched": False, "details": {}}

        # 模式匹配
        if rule.pattern:
            payload = packet_data.get("payload", "")
            if rule.pattern_type == "regex":
                try:
                    if not re.search(rule.pattern, payload, re.IGNORECASE):
                        return {"matched": False, "details": {}}
                except re.error:
                    return {"matched": False, "details": {}}
            elif rule.pattern_type == "content":
                if rule.pattern.lower() not in payload.lower():
                    return {"matched": False, "details": {}}

        return {
            "matched": True,
            "details": {
                "protocol": packet_data.get("protocol"),
                "src_ip": packet_data.get("src_ip"),
                "dst_ip": packet_data.get("dst_ip"),
                "dst_port": packet_data.get("dst_port"),
            },
        }

    def _parse_port_range(self, port_spec: str) -> List[int]:
        """解析端口范围字符串，如 '80,443,8000-9000'"""
        ports = []
        for part in port_spec.split(","):
            part = part.strip()
            if "-" in part:
                start, end = part.split("-", 1)
                ports.extend(range(int(start), int(end) + 1))
            else:
                try:
                    ports.append(int(part))
                except ValueError:
                    continue
        return ports

    def get_metrics(self) -> Dict[str, Any]:
        """获取IDS优化指标"""
        return {
            **self._metrics,
            "rule_stats_count": len(self._rule_stats),
            "optimization_history_size": len(self._optimization_history),
        }

    def get_optimization_history(self, limit: int = 10) -> List[Dict]:
        """获取优化历史记录"""
        return self._optimization_history[-limit:]
