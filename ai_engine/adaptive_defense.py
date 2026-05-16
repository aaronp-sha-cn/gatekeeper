"""
GateKeeper - 自适应防御引擎
基于威胁情报和AI分析结果，动态调整防御策略
"""

import threading
import time
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
from collections import defaultdict, deque

from config.settings import settings
from config.logging_config import get_logger, log_security_event
from core.database import db_manager
from core.models import (
    Alert, AlertLevel, ThreatIntel, ThreatLevel,
    FirewallRule, FirewallAction, ProtocolType
)

logger = get_logger("adaptive_defense")


class AdaptiveDefense:
    """
    自适应防御引擎
    根据威胁情报、异常检测结果和历史攻击模式，自动调整防御策略
    """

    def __init__(self):
        self._lock = threading.Lock()
        # 延迟导入避免循环依赖: ai_engine -> network.firewall -> core.database -> core.app -> ai_engine
        from network.firewall import FirewallManager
        self._firewall = FirewallManager()

        # 威胁评分缓存
        self._ip_threat_scores: Dict[str, float] = {}
        self._ip_block_list: set = set()
        self._ip_watch_list: set = set()

        # 攻击模式历史
        self._attack_patterns: deque = deque(maxlen=10000)
        self._defense_actions: deque = deque(maxlen=1000)

        # 配置
        self._block_threshold = 0.85  # 自动封禁阈值
        self._watch_threshold = 0.6   # 观察阈值
        self._block_duration = 3600   # 默认封禁时长（秒）
        self._max_blocked_ips = 10000  # 最大封禁IP数

        # 统计
        self._stats = {
            "total_blocks": 0,
            "total_unblocks": 0,
            "auto_rules_created": 0,
            "threats_mitigated": 0,
        }

        logger.info("自适应防御引擎初始化完成")

    def evaluate_threat(self, ip_address: str) -> Dict[str, Any]:
        """
        评估IP地址的威胁等级

        Args:
            ip_address: 要评估的IP地址

        Returns:
            威胁评估结果
        """
        score = 0.0
        factors = []

        # 因素1: 威胁情报匹配
        intel_score = self._check_threat_intel(ip_address)
        if intel_score > 0:
            score += intel_score * settings.ai_model.threat_score_weights["threat_intel_match"]
            factors.append({"source": "threat_intel", "score": intel_score})

        # 因素2: 流量异常
        traffic_score = self._check_traffic_anomaly(ip_address)
        if traffic_score > 0:
            score += traffic_score * settings.ai_model.threat_score_weights["traffic_volume"]
            factors.append({"source": "traffic_anomaly", "score": traffic_score})

        # 因素3: 行为异常
        behavior_score = self._check_behavior_anomaly(ip_address)
        if behavior_score > 0:
            score += behavior_score * settings.ai_model.threat_score_weights["behavior_anomaly"]
            factors.append({"source": "behavior_anomaly", "score": behavior_score})

        # 因素4: 协议异常
        protocol_score = self._check_protocol_anomaly(ip_address)
        if protocol_score > 0:
            score += protocol_score * settings.ai_model.threat_score_weights["protocol_anomaly"]
            factors.append({"source": "protocol_anomaly", "score": protocol_score})

        # 限制分数范围
        score = min(1.0, max(0.0, score))

        # 更新缓存
        with self._lock:
            self._ip_threat_scores[ip_address] = score

        # 确定建议动作
        if score >= self._block_threshold:
            action = "block"
        elif score >= self._watch_threshold:
            action = "watch"
        else:
            action = "allow"

        return {
            "ip_address": ip_address,
            "threat_score": round(score, 4),
            "action": action,
            "factors": factors,
            "timestamp": datetime.now().isoformat(),
        }

    def _check_threat_intel(self, ip_address: str) -> float:
        """检查威胁情报数据库"""
        try:
            with db_manager.get_session() as session:
                intel = (
                    session.query(ThreatIntel)
                    .filter_by(
                        indicator_type="ip",
                        indicator_value=ip_address,
                        is_active=True,
                    )
                    .first()
                )
                if intel:
                    if intel.threat_level == ThreatLevel.CRITICAL:
                        return 1.0
                    elif intel.threat_level == ThreatLevel.HIGH:
                        return 0.8
                    elif intel.threat_level == ThreatLevel.MEDIUM:
                        return 0.5
                    elif intel.threat_level == ThreatLevel.LOW:
                        return 0.3
        except Exception as e:
            logger.debug("查询威胁情报失败: {}".format(e))
        return 0.0

    def _check_traffic_anomaly(self, ip_address: str) -> float:
        """检查流量异常"""
        try:
            from core.models import TrafficLog
            from datetime import datetime, timedelta

            with db_manager.get_session() as session:
                one_hour_ago = datetime.now() - timedelta(hours=1)
                count = (
                    session.query(TrafficLog)
                    .filter(TrafficLog.source_ip == ip_address)
                    .filter(TrafficLog.timestamp >= one_hour_ago)
                    .count()
                )

                # 基于流量量的评分
                if count > 10000:
                    return 1.0
                elif count > 5000:
                    return 0.8
                elif count > 1000:
                    return 0.5
                elif count > 500:
                    return 0.3
        except Exception:
            pass
        return 0.0

    def _check_behavior_anomaly(self, ip_address: str) -> float:
        """检查行为异常（如端口扫描）"""
        try:
            from core.models import TrafficLog
            from datetime import datetime, timedelta
            from sqlalchemy import func

            with db_manager.get_session() as session:
                one_hour_ago = datetime.now() - timedelta(hours=1)
                # 检查连接的不同目标端口数
                distinct_ports = (
                    session.query(func.count(func.distinct(TrafficLog.dest_port)))
                    .filter(TrafficLog.source_ip == ip_address)
                    .filter(TrafficLog.timestamp >= one_hour_ago)
                    .scalar()
                )

                if distinct_ports and distinct_ports > 100:
                    return 1.0  # 疑似端口扫描
                elif distinct_ports and distinct_ports > 50:
                    return 0.7
                elif distinct_ports and distinct_ports > 20:
                    return 0.4
        except Exception:
            pass
        return 0.0

    def _check_protocol_anomaly(self, ip_address: str) -> float:
        """检查协议异常"""
        try:
            from core.models import TrafficLog
            from datetime import datetime, timedelta
            from sqlalchemy import func

            with db_manager.get_session() as session:
                one_hour_ago = datetime.now() - timedelta(hours=1)
                # 检查ICMP流量比例
                total = (
                    session.query(func.count(TrafficLog.id))
                    .filter(TrafficLog.source_ip == ip_address)
                    .filter(TrafficLog.timestamp >= one_hour_ago)
                    .scalar()
                )
                icmp_count = (
                    session.query(func.count(TrafficLog.id))
                    .filter(TrafficLog.source_ip == ip_address)
                    .filter(TrafficLog.protocol == "ICMP")
                    .filter(TrafficLog.timestamp >= one_hour_ago)
                    .scalar()
                )

                if total and total > 100:
                    icmp_ratio = icmp_count / total
                    if icmp_ratio > 0.8:
                        return 0.9  # 疑似ICMP洪水
                    elif icmp_ratio > 0.5:
                        return 0.5
        except Exception:
            pass
        return 0.0

    def auto_block_ip(
        self,
        ip_address: str,
        reason: str = "auto_defense",
        duration: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        自动封禁IP地址

        Args:
            ip_address: 要封禁的IP
            reason: 封禁原因
            duration: 封禁时长（秒），None表示永久

        Returns:
            封禁结果
        """
        with self._lock:
            if len(self._ip_block_list) >= self._max_blocked_ips:
                return {
                    "status": "error",
                    "message": "封禁列表已满",
                }

            self._ip_block_list.add(ip_address)
            self._stats["total_blocks"] += 1

        # 添加防火墙规则
        rule_name = "AUTO-BLOCK-{}-{}".format(ip_address, int(time.time()))
        result = self._firewall.add_rule(
            name=rule_name,
            source_ip=ip_address,
            action="DROP",
            description="自动封禁: {}".format(reason),
        )

        # 记录防御动作
        self._defense_actions.append({
            "action": "block",
            "ip": ip_address,
            "reason": reason,
            "duration": duration,
            "timestamp": datetime.now().isoformat(),
            "firewall_result": result,
        })

        log_security_event(
            user="system",
            action="auto_block",
            resource=ip_address,
            result="success",
            message="自动封禁IP: {}, 原因: {}".format(ip_address, reason)
        )

        logger.warning("自动封禁IP: {}, 原因: {}".format(ip_address, reason))
        return {"status": "ok", "ip": ip_address, "rule_name": rule_name}

    def auto_unblock_ip(self, ip_address: str) -> Dict[str, Any]:
        """自动解封IP地址"""
        with self._lock:
            if ip_address in self._ip_block_list:
                self._ip_block_list.discard(ip_address)
                self._stats["total_unblocks"] += 1

        # 移除防火墙规则
        result = self._firewall.remove_rule_by_source(ip_address)

        self._defense_actions.append({
            "action": "unblock",
            "ip": ip_address,
            "timestamp": datetime.now().isoformat(),
            "firewall_result": result,
        })

        logger.info("自动解封IP: {}".format(ip_address))
        return {"status": "ok", "ip": ip_address}

    def process_alert(self, alert: Alert) -> Optional[Dict[str, Any]]:
        """
        处理安全告警，根据告警级别自动采取防御措施

        Args:
            alert: 告警对象

        Returns:
            采取的防御措施或None
        """
        action_taken = None

        if alert.level == AlertLevel.CRITICAL:
            # 严重告警: 自动封禁源IP
            if alert.source_ip and alert.source_ip not in ("0.0.0.0", ""):
                result = self.auto_block_ip(
                    alert.source_ip,
                    reason="critical_alert: {}".format(alert.title),
                )
                action_taken = result
                self._stats["threats_mitigated"] += 1

        elif alert.level == AlertLevel.HIGH:
            # 高危告警: 评估后决定是否封禁
            if alert.source_ip and alert.source_ip not in ("0.0.0.0", ""):
                evaluation = self.evaluate_threat(alert.source_ip)
                if evaluation["action"] == "block":
                    result = self.auto_block_ip(
                        alert.source_ip,
                        reason="high_alert_evaluated: {}".format(alert.title),
                    )
                    action_taken = result
                    self._stats["threats_mitigated"] += 1
                elif evaluation["action"] == "watch":
                    with self._lock:
                        self._ip_watch_list.add(alert.source_ip)

        return action_taken

    def run_adaptive_cycle(self) -> Dict[str, Any]:
        """
        执行一轮自适应防御周期
        检查观察列表中的IP，清理过期封禁
        """
        actions_taken = []

        # 检查观察列表
        with self._lock:
            watch_list_copy = list(self._ip_watch_list)

        for ip in watch_list_copy:
            evaluation = self.evaluate_threat(ip)
            if evaluation["action"] == "block":
                result = self.auto_block_ip(
                    ip, reason="watch_list_promotion"
                )
                actions_taken.append(result)
                self._ip_watch_list.discard(ip)
            elif evaluation["action"] == "allow":
                self._ip_watch_list.discard(ip)

        # 清理过期封禁（评分降低的IP）
        with self._lock:
            block_list_copy = list(self._ip_block_list)

        for ip in block_list_copy:
            evaluation = self.evaluate_threat(ip)
            if evaluation["threat_score"] < self._watch_threshold:
                self.auto_unblock_ip(ip)
                actions_taken.append({"action": "unblock", "ip": ip})

        logger.info(
            "自适应防御周期完成: 采取{}项措施".format(len(actions_taken))
        )

        return {
            "status": "ok",
            "timestamp": datetime.now().isoformat(),
            "actions_taken": len(actions_taken),
            "watch_list_size": len(self._ip_watch_list),
            "block_list_size": len(self._ip_block_list),
        }

    def get_blocked_ips(self) -> List[str]:
        """获取当前封禁的IP列表"""
        with self._lock:
            return list(self._ip_block_list)

    def get_watched_ips(self) -> List[str]:
        """获取当前观察的IP列表"""
        with self._lock:
            return list(self._ip_watch_list)

    def get_threat_score(self, ip_address: str) -> float:
        """获取IP威胁评分"""
        return self._ip_threat_scores.get(ip_address, 0.0)

    def get_statistics(self) -> Dict[str, Any]:
        """获取防御统计"""
        return {
            **self._stats,
            "blocked_ips_count": len(self._ip_block_list),
            "watched_ips_count": len(self._ip_watch_list),
            "defense_actions_count": len(self._defense_actions),
            "recent_actions": list(self._defense_actions)[-10:],
        }
