"""
GateKeeper - 报表生成器
生成各类安全报表，包括日报、安全审计报告、流量分析报告等
"""

from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta

from config.logging_config import get_logger
from core.database import db_manager
from core.models import Alert, TrafficLog, ScanResult, Vulnerability, ThreatIntel, FirewallRule

logger = get_logger("report_generator")


class ReportGenerator:
    """
    报表生成器
    支持多种类型的报表生成
    """

    def __init__(self):
        self._report_cache: Dict[str, Dict] = {}
        logger.info("报表生成器初始化完成")

    def generate_daily_report(self) -> Dict[str, Any]:
        """
        生成每日安全报告

        Returns:
            报表数据
        """
        now = datetime.now()
        yesterday = now - timedelta(days=1)

        report = {
            "type": "daily",
            "title": "GateKeeper 每日安全报告 - {}".format(yesterday.strftime('%Y-%m-%d')),
            "generated_at": now.isoformat(),
            "period": {
                "from": yesterday.isoformat(),
                "to": now.isoformat(),
            },
            "sections": {},
        }

        # 告警摘要
        report["sections"]["alerts"] = self._get_alert_summary(yesterday, now)

        # 流量摘要
        report["sections"]["traffic"] = self._get_traffic_summary(yesterday, now)

        # 漏洞摘要
        report["sections"]["vulnerabilities"] = self._get_vuln_summary()

        # 防火墙摘要
        report["sections"]["firewall"] = self._get_firewall_summary()

        # 威胁情报摘要
        report["sections"]["threat_intel"] = self._get_threat_intel_summary()

        # 扫描摘要
        report["sections"]["scans"] = self._get_scan_summary(yesterday, now)

        logger.info("每日报告生成完成: {}".format(report['title']))
        return report

    def generate_security_report(
        self,
        date_from: str = "",
        date_to: str = "",
    ) -> Dict[str, Any]:
        """
        生成安全审计报告

        Args:
            date_from: 开始日期
            date_to: 结束日期

        Returns:
            报表数据
        """
        now = datetime.now()
        from_date = datetime.fromisoformat(date_from) if date_from else now - timedelta(days=7)
        to_date = datetime.fromisoformat(date_to) if date_to else now

        report = {
            "type": "security_audit",
            "title": "安全审计报告 - {} ~ {}".format(from_date.strftime('%Y-%m-%d'), to_date.strftime('%Y-%m-%d')),
            "generated_at": now.isoformat(),
            "period": {
                "from": from_date.isoformat(),
                "to": to_date.isoformat(),
            },
            "sections": {},
        }

        # 详细告警分析
        report["sections"]["alert_analysis"] = self._get_alert_analysis(from_date, to_date)

        # 漏洞趋势
        report["sections"]["vuln_trend"] = self._get_vuln_trend(from_date, to_date)

        # 防御措施效果
        report["sections"]["defense_effectiveness"] = self._get_defense_effectiveness(from_date, to_date)

        # 建议
        report["sections"]["recommendations"] = self._generate_recommendations(report)

        logger.info("安全审计报告生成完成")
        return report

    def generate_traffic_report(
        self,
        date_from: str = "",
        date_to: str = "",
    ) -> Dict[str, Any]:
        """
        生成流量分析报告

        Args:
            date_from: 开始日期
            date_to: 结束日期

        Returns:
            报表数据
        """
        now = datetime.now()
        from_date = datetime.fromisoformat(date_from) if date_from else now - timedelta(days=1)
        to_date = datetime.fromisoformat(date_to) if date_to else now

        report = {
            "type": "traffic_analysis",
            "title": "流量分析报告 - {} ~ {}".format(from_date.strftime('%Y-%m-%d'), to_date.strftime('%Y-%m-%d')),
            "generated_at": now.isoformat(),
            "period": {
                "from": from_date.isoformat(),
                "to": to_date.isoformat(),
            },
            "sections": {},
        }

        report["sections"]["traffic_overview"] = self._get_traffic_summary(from_date, to_date)
        report["sections"]["protocol_distribution"] = self._get_protocol_distribution(from_date, to_date)
        report["sections"]["top_sources"] = self._get_top_sources(from_date, to_date)
        report["sections"]["top_destinations"] = self._get_top_destinations(from_date, to_date)

        logger.info("流量分析报告生成完成")
        return report

    def _get_alert_summary(self, from_date: datetime, to_date: datetime) -> Dict[str, Any]:
        """获取告警摘要"""
        try:
            from sqlalchemy import func
            with db_manager.get_session() as session:
                total = (
                    session.query(Alert)
                    .filter(Alert.created_at.between(from_date, to_date))
                    .count()
                )
                by_level = (
                    session.query(Alert.level, func.count(Alert.id))
                    .filter(Alert.created_at.between(from_date, to_date))
                    .group_by(Alert.level)
                    .all()
                )
                by_source = (
                    session.query(Alert.source, func.count(Alert.id))
                    .filter(Alert.created_at.between(from_date, to_date))
                    .group_by(Alert.source)
                    .all()
                )

                return {
                    "total": total,
                    "by_level": {l.value: c for l, c in by_level},
                    "by_source": {s: c for s, c in by_source},
                }
        except Exception as e:
            logger.error("获取告警摘要失败: {}".format(e))
            return {"total": 0, "error": str(e)}

    def _get_traffic_summary(self, from_date: datetime, to_date: datetime) -> Dict[str, Any]:
        """获取流量摘要"""
        try:
            from sqlalchemy import func
            with db_manager.get_session() as session:
                total_packets = (
                    session.query(func.count(TrafficLog.id))
                    .filter(TrafficLog.timestamp.between(from_date, to_date))
                    .scalar()
                )
                total_bytes = (
                    session.query(func.sum(TrafficLog.packet_length))
                    .filter(TrafficLog.timestamp.between(from_date, to_date))
                    .scalar()
                )
                anomaly_count = (
                    session.query(func.count(TrafficLog.id))
                    .filter(
                        TrafficLog.timestamp.between(from_date, to_date),
                        TrafficLog.is_anomaly == True,
                    )
                    .scalar()
                )

                return {
                    "total_packets": total_packets or 0,
                    "total_bytes": int(total_bytes or 0),
                    "anomaly_packets": anomaly_count or 0,
                    "anomaly_rate": round(
                        (anomaly_count or 0) / max(total_packets, 1), 4
                    ),
                }
        except Exception as e:
            logger.error("获取流量摘要失败: {}".format(e))
            return {"total_packets": 0, "error": str(e)}

    def _get_vuln_summary(self) -> Dict[str, Any]:
        """获取漏洞摘要"""
        try:
            from sqlalchemy import func
            with db_manager.get_session() as session:
                total = session.query(Vulnerability).count()
                unfixed = session.query(Vulnerability).filter_by(is_fixed=False).count()
                by_severity = (
                    session.query(Vulnerability.severity, func.count(Vulnerability.id))
                    .group_by(Vulnerability.severity)
                    .all()
                )

                return {
                    "total": total,
                    "unfixed": unfixed,
                    "by_severity": {s.value: c for s, c in by_severity},
                }
        except Exception as e:
            return {"total": 0, "error": str(e)}

    def _get_firewall_summary(self) -> Dict[str, Any]:
        """获取防火墙摘要"""
        try:
            with db_manager.get_session() as session:
                total = session.query(FirewallRule).count()
                active = session.query(FirewallRule).filter_by(is_enabled=True).count()
                return {
                    "total_rules": total,
                    "active_rules": active,
                }
        except Exception:
            return {"total_rules": 0, "active_rules": 0}

    def _get_threat_intel_summary(self) -> Dict[str, Any]:
        """获取威胁情报摘要"""
        try:
            from sqlalchemy import func
            with db_manager.get_session() as session:
                total = session.query(ThreatIntel).filter_by(is_active=True).count()
                by_type = (
                    session.query(ThreatIntel.indicator_type, func.count(ThreatIntel.id))
                    .filter_by(is_active=True)
                    .group_by(ThreatIntel.indicator_type)
                    .all()
                )
                return {
                    "active_indicators": total,
                    "by_type": {t: c for t, c in by_type},
                }
        except Exception:
            return {"active_indicators": 0}

    def _get_scan_summary(self, from_date: datetime, to_date: datetime) -> Dict[str, Any]:
        """获取扫描摘要"""
        try:
            with db_manager.get_session() as session:
                scans = (
                    session.query(ScanResult)
                    .filter(ScanResult.created_at.between(from_date, to_date))
                    .all()
                )
                return {
                    "total_scans": len(scans),
                    "completed": len([s for s in scans if s.status.value == "completed"]),
                }
        except Exception:
            return {"total_scans": 0, "completed": 0}

    def _get_alert_analysis(self, from_date: datetime, to_date: datetime) -> Dict:
        """告警分析"""
        summary = self._get_alert_summary(from_date, to_date)
        summary["analysis"] = "告警趋势分析数据"
        return summary

    def _get_vuln_trend(self, from_date: datetime, to_date: datetime) -> Dict:
        """漏洞趋势"""
        return self._get_vuln_summary()

    def _get_defense_effectiveness(self, from_date: datetime, to_date: datetime) -> Dict:
        """防御效果"""
        alerts = self._get_alert_summary(from_date, to_date)
        total = alerts.get("total", 0)
        return {
            "total_alerts": total,
            "defense_rate": round(1.0 - min(total / max(total * 2, 1), 1.0), 4),
        }

    def _generate_recommendations(self, report: Dict) -> List[str]:
        """生成安全建议"""
        recommendations = []
        vulns = report.get("sections", {}).get("vulnerabilities", {})
        if vulns.get("unfixed", 0) > 0:
            recommendations.append(
                "当前有 {} 个未修复漏洞，建议优先处理严重和高危漏洞".format(vulns['unfixed'])
            )
        alerts = report.get("sections", {}).get("alerts", {})
        if alerts.get("total", 0) > 100:
            recommendations.append("告警数量较多，建议检查是否存在持续攻击")
        if not recommendations:
            recommendations.append("系统安全状况良好，继续保持当前防御策略")
        return recommendations

    def _get_protocol_distribution(self, from_date: datetime, to_date: datetime) -> Dict:
        """协议分布"""
        try:
            from sqlalchemy import func
            with db_manager.get_session() as session:
                results = (
                    session.query(TrafficLog.protocol, func.count(TrafficLog.id))
                    .filter(TrafficLog.timestamp.between(from_date, to_date))
                    .group_by(TrafficLog.protocol)
                    .all()
                )
                return dict(results)
        except Exception:
            return {}

    def _get_top_sources(self, from_date: datetime, to_date: datetime, limit: int = 10) -> List:
        """Top源IP"""
        try:
            from sqlalchemy import func
            with db_manager.get_session() as session:
                results = (
                    session.query(TrafficLog.source_ip, func.count(TrafficLog.id))
                    .filter(TrafficLog.timestamp.between(from_date, to_date))
                    .group_by(TrafficLog.source_ip)
                    .order_by(func.count(TrafficLog.id).desc())
                    .limit(limit)
                    .all()
                )
                return [{"ip": ip, "count": c} for ip, c in results]
        except Exception:
            return []

    def _get_top_destinations(self, from_date: datetime, to_date: datetime, limit: int = 10) -> List:
        """Top目标IP"""
        try:
            from sqlalchemy import func
            with db_manager.get_session() as session:
                results = (
                    session.query(TrafficLog.dest_ip, func.count(TrafficLog.id))
                    .filter(TrafficLog.timestamp.between(from_date, to_date))
                    .group_by(TrafficLog.dest_ip)
                    .order_by(func.count(TrafficLog.id).desc())
                    .limit(limit)
                    .all()
                )
                return [{"ip": ip, "count": c} for ip, c in results]
        except Exception:
            return []

    def list_reports(self) -> List[Dict]:
        """列出已生成的报表"""
        return [
            {
                "id": k,
                "type": v.get("type", "unknown"),
                "title": v.get("title", ""),
                "generated_at": v.get("generated_at", ""),
            }
            for k, v in self._report_cache.items()
        ]
