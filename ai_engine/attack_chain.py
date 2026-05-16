"""
GateKeeper - 攻击链分析器
多阶段攻击关联分析与可视化
"""

import logging
import threading
import time
from typing import Dict, List, Optional, Any
from datetime import datetime
from collections import defaultdict, deque

logger = logging.getLogger(__name__)

# 模块级单例
_instance = None
_instance_lock = threading.Lock()

# 攻击链阶段定义
ATTACK_STAGES = {
    "recon": {"order": 1, "label": "侦察扫描", "keywords": ["scan", "recon", "probe", "enumerate", "discover"]},
    "initial_access": {"order": 2, "label": "初始访问", "keywords": ["brute_force", "phishing", "exploit", "injection", "login"]},
    "lateral_movement": {"order": 3, "label": "横向移动", "keywords": ["lateral", "pivot", "pass_the_hash", "remote_exec"]},
    "privilege_escalation": {"order": 4, "label": "权限提升", "keywords": ["privilege", "escalate", "sudo", "root", "admin"]},
    "persistence": {"order": 5, "label": "持久化", "keywords": ["persistence", "backdoor", "cron", "startup", "rootkit"]},
    "exfiltration": {"order": 6, "label": "数据窃取", "keywords": ["exfil", "data_transfer", "dns_tunnel", "upload"]},
    "impact": {"order": 7, "label": "破坏影响", "keywords": ["ransomware", "destroy", "wipe", "dos", "damage"]},
}


class AttackChainAnalyzer:
    """
    攻击链分析器
    关联多阶段安全事件，构建攻击链视图，支持按IP查询攻击链
    """

    def __init__(self):
        self._lock = threading.Lock()

        # 安全事件存储
        self._events: deque = deque(maxlen=50000)

        # IP关联事件索引: {ip: [event_index, ...]}
        self._ip_index: Dict[str, List[int]] = defaultdict(list)

        # 攻击链缓存: {ip: attack_chain_dict}
        self._chain_cache: Dict[str, Dict[str, Any]] = {}
        self._cache_ttl = 60  # 缓存有效期（秒）

        # 统计
        self._stats = {
            "total_events": 0,
            "total_chains_built": 0,
            "total_correlations": 0,
            "unique_ips": 0,
        }

        logger.info("攻击链分析器初始化完成")

    def add_event(self, event: Dict[str, Any]) -> None:
        """
        添加安全事件

        Args:
            event: 事件字典，应包含以下字段:
                - source_ip: 源IP地址
                - dest_ip: 目标IP地址
                - event_type: 事件类型
                - timestamp: 事件时间（datetime对象或ISO格式字符串）
                - severity: 严重程度
                - title: 事件标题
                - source: 事件来源
        """
        with self._lock:
            # 规范化时间戳
            ts = event.get("timestamp")
            if isinstance(ts, datetime):
                event["timestamp"] = ts
                event["timestamp_iso"] = ts.isoformat()
            elif isinstance(ts, str):
                event["timestamp_iso"] = ts
                try:
                    event["timestamp"] = datetime.fromisoformat(ts)
                except (ValueError, TypeError):
                    event["timestamp"] = datetime.now()
                    event["timestamp_iso"] = event["timestamp"].isoformat()
            else:
                event["timestamp"] = datetime.now()
                event["timestamp_iso"] = event["timestamp"].isoformat()

            # 分类攻击阶段
            event["stage"] = self._classify_stage(event)

            # 存储事件
            event_index = len(self._events)
            self._events.append(event)

            # 更新IP索引
            source_ip = event.get("source_ip", "")
            dest_ip = event.get("dest_ip", "")

            if source_ip:
                self._ip_index[source_ip].append(event_index)
            if dest_ip:
                self._ip_index[dest_ip].append(event_index)

            # 更新统计
            self._stats["total_events"] += 1
            self._stats["unique_ips"] = len(self._ip_index)

            # 清除相关IP的缓存
            for ip in (source_ip, dest_ip):
                if ip and ip in self._chain_cache:
                    del self._chain_cache[ip]

            logger.debug(
                "添加安全事件: type={}, src={}, dst={}, stage={}".format(
                    event.get("event_type", "unknown"),
                    source_ip, dest_ip, event["stage"]
                )
            )

    def get_attack_chain(self, ip: str) -> Dict[str, Any]:
        """
        获取指定IP的攻击链分析

        Args:
            ip: IP地址

        Returns:
            攻击链字典，包含以下字段:
                - ip: 查询的IP地址
                - total_events: 关联事件总数
                - chain_stages: 攻击链阶段列表
                - events: 关联事件列表
                - by_severity: 按严重程度统计
                - by_source: 按来源统计
                - by_type: 按事件类型统计
                - risk_level: 风险等级评估
        """
        with self._lock:
            self._stats["total_chains_built"] += 1

            ip = ip.strip()
            ip_lower = ip.lower()

            # 检查缓存
            cached = self._chain_cache.get(ip)
            if cached and (time.time() - cached.get("_cached_at", 0)) < self._cache_ttl:
                result = {k: v for k, v in cached.items() if not k.startswith("_")}
                return result

            # 查找关联事件
            event_indices = self._ip_index.get(ip, [])
            related_events = [self._events[i] for i in event_indices if i < len(self._events)]

            # 按时间排序
            related_events.sort(key=lambda e: e.get("timestamp") or datetime.min)

            # 构建攻击链阶段
            chain_stages = []
            seen_stages = set()

            for evt in related_events:
                stage = evt.get("stage", "unknown")
                if stage not in seen_stages:
                    seen_stages.add(stage)
                    stage_info = ATTACK_STAGES.get(stage, {"order": 99, "label": stage})
                    chain_stages.append({
                        "stage": stage_info.get("label", stage),
                        "stage_key": stage,
                        "order": stage_info.get("order", 99),
                        "timestamp": evt.get("timestamp_iso"),
                        "event_type": evt.get("event_type", "unknown"),
                        "title": evt.get("title", ""),
                        "severity": evt.get("severity", "medium"),
                        "source": evt.get("source", ""),
                    })

            # 按阶段顺序排序
            chain_stages.sort(key=lambda s: s.get("order", 99))

            # 统计
            severity_counts = defaultdict(int)
            source_counts = defaultdict(int)
            type_counts = defaultdict(int)

            for evt in related_events:
                severity_counts[evt.get("severity", "unknown")] += 1
                source_counts[evt.get("source", "unknown")] += 1
                type_counts[evt.get("event_type", "unknown")] += 1

            # 评估风险等级
            risk_level = self._assess_chain_risk(chain_stages, len(related_events))

            result = {
                "ip": ip,
                "total_events": len(related_events),
                "chain_stages": chain_stages,
                "events": related_events[:100],
                "by_severity": dict(severity_counts),
                "by_source": dict(source_counts),
                "by_type": dict(type_counts),
                "risk_level": risk_level,
            }

            # 更新缓存
            result["_cached_at"] = time.time()
            self._chain_cache[ip] = result

            logger.info(
                "攻击链分析: ip={}, events={}, stages={}, risk={}".format(
                    ip, len(related_events), len(chain_stages), risk_level
                )
            )

            return result

    def correlate_events(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        关联分析多个事件，识别可能的攻击模式

        Args:
            events: 事件列表

        Returns:
            关联结果列表，每组包含相关事件和关联原因
        """
        with self._lock:
            self._stats["total_correlations"] += 1

            if len(events) < 2:
                return []

            correlations = []

            # 按IP分组
            ip_groups: Dict[str, List[Dict]] = defaultdict(list)
            for evt in events:
                src = evt.get("source_ip", "")
                dst = evt.get("dest_ip", "")
                if src:
                    ip_groups[src].append(evt)
                if dst:
                    ip_groups[dst].append(evt)

            # 分析每个IP组内的事件关联
            for ip, group_events in ip_groups.items():
                if len(group_events) < 2:
                    continue

                # 按时间排序
                group_events.sort(key=lambda e: e.get("timestamp") or datetime.min)

                # 检测多阶段攻击模式
                stages_seen = set()
                for evt in group_events:
                    stage = self._classify_stage(evt)
                    stages_seen.add(stage)

                # 时间窗口分析（1小时内多个事件视为关联）
                time_span = 0.0
                if len(group_events) >= 2:
                    first_ts = group_events[0].get("timestamp")
                    last_ts = group_events[-1].get("timestamp")
                    if first_ts and last_ts:
                        time_span = (last_ts - first_ts).total_seconds()

                is_correlated = (
                    len(stages_seen) >= 2 or  # 多个不同阶段
                    (time_span > 0 and time_span <= 3600 and len(group_events) >= 3)  # 短时间密集事件
                )

                if is_correlated:
                    correlations.append({
                        "ip": ip,
                        "event_count": len(group_events),
                        "stages_detected": list(stages_seen),
                        "time_span_seconds": round(time_span, 2),
                        "correlation_type": "multi_stage" if len(stages_seen) >= 2 else "burst",
                        "events": group_events[:50],
                        "risk_level": self._assess_chain_risk(
                            [{"stage": s} for s in stages_seen],
                            len(group_events),
                        ),
                    })

            # 按风险等级排序
            risk_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
            correlations.sort(key=lambda c: risk_order.get(c.get("risk_level", "low"), 4))

            logger.info(
                "事件关联分析: 输入{}条事件, 发现{}组关联".format(
                    len(events), len(correlations)
                )
            )

            return correlations

    def _classify_stage(self, event: Dict[str, Any]) -> str:
        """
        将事件分类到攻击链阶段

        Args:
            event: 事件字典

        Returns:
            阶段标识字符串
        """
        event_type = str(event.get("event_type", "")).lower()
        title = str(event.get("title", "")).lower()
        tags = event.get("tags", [])
        if isinstance(tags, list):
            tags_str = " ".join(str(t).lower() for t in tags)
        else:
            tags_str = str(tags).lower()

        combined_text = "{} {} {}".format(event_type, title, tags_str)

        best_stage = "unknown"
        best_match_count = 0

        for stage_name, stage_info in ATTACK_STAGES.items():
            match_count = sum(1 for kw in stage_info["keywords"] if kw in combined_text)
            if match_count > best_match_count:
                best_match_count = match_count
                best_stage = stage_name

        return best_stage

    def _assess_chain_risk(self, chain_stages: List[Dict], event_count: int) -> str:
        """
        根据攻击链阶段和事件数量评估风险等级

        Args:
            chain_stages: 攻击链阶段列表
            event_count: 关联事件总数

        Returns:
            风险等级字符串
        """
        stage_count = len(chain_stages)

        # 检查是否包含高危阶段
        high_risk_stages = {"privilege_escalation", "exfiltration", "impact", "persistence"}
        has_high_risk = any(
            s.get("stage_key", "") in high_risk_stages for s in chain_stages
        )

        if stage_count >= 4 or (has_high_risk and stage_count >= 2):
            return "critical"
        elif stage_count >= 3 or (has_high_risk and event_count >= 5):
            return "high"
        elif stage_count >= 2 or event_count >= 10:
            return "medium"
        else:
            return "low"

    def get_stats(self) -> Dict[str, Any]:
        """
        获取攻击链分析器统计信息

        Returns:
            统计数据字典
        """
        with self._lock:
            return {
                **self._stats,
                "cache_size": len(self._chain_cache),
                "index_size": len(self._ip_index),
            }


def get_attack_chain_analyzer() -> AttackChainAnalyzer:
    """
    获取攻击链分析器单例

    Returns:
        AttackChainAnalyzer 实例
    """
    global _instance
    if _instance is None:
        with _instance_lock:
            if _instance is None:
                _instance = AttackChainAnalyzer()
    return _instance
