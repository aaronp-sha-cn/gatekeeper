"""
GateKeeper - 操作审计日志管理器
提供Web/CLI操作日志记录、查询和导出功能
"""

import functools
import json
import csv
import io
import sqlalchemy
from datetime import datetime, timedelta
from typing import Optional, List, Dict

from config.logging_config import get_logger
from core.database import db_manager
from core.models import AuditLog

logger = get_logger("audit")


class AuditLogger:
    """操作审计日志管理器"""

    def log(self, source: str, action: str, module: str = "",
            username: str = "", detail: str = "",
            client_ip: str = "", user_agent: str = "",
            result: str = "success", error_message: str = "",
            request_data: dict = None):
        """
        记录操作日志

        Args:
            source: 来源 (web / cli / api / system)
            action: 操作类型 (login / logout / config_change / rule_add ...)
            module: 功能模块 (gateway / firewall / ids / settings ...)
            username: 操作用户
            detail: 操作详情
            client_ip: 客户端IP
            user_agent: 浏览器UA
            result: 结果 (success / failure)
            error_message: 错误信息
            request_data: 请求数据
        """
        try:
            log_entry = AuditLog(
                timestamp=datetime.now(),
                source=source,
                username=username or "system",
                action=action,
                module=module,
                detail=detail,
                client_ip=client_ip,
                user_agent=user_agent[:256] if user_agent else None,
                result=result,
                error_message=error_message,
                request_data=json.dumps(request_data, ensure_ascii=False) if request_data else None,
            )
            db_manager.add(log_entry)
        except Exception as e:
            logger.debug("写入审计日志失败: {}".format(e))

    def query(self, source: str = None, username: str = None,
              action: str = None, module: str = None,
              result: str = None, keyword: str = None,
              start_time: datetime = None, end_time: datetime = None,
              page: int = 1, page_size: int = 50) -> Dict:
        """
        查询操作日志

        Returns:
            {"total": int, "page": int, "page_size": int, "records": list}
        """
        try:
            with db_manager.get_session() as session:
                query = session.query(AuditLog)

                if source:
                    query = query.filter(AuditLog.source == source)
                if username:
                    query = query.filter(AuditLog.username == username)
                if action:
                    query = query.filter(AuditLog.action == action)
                if module:
                    query = query.filter(AuditLog.module == module)
                if result:
                    query = query.filter(AuditLog.result == result)
                if keyword:
                    like = "%{}%".format(keyword)
                    query = query.filter(AuditLog.detail.ilike(like))
                if start_time:
                    query = query.filter(AuditLog.timestamp >= start_time)
                if end_time:
                    query = query.filter(AuditLog.timestamp <= end_time)

                total = query.count()
                records = query.order_by(AuditLog.timestamp.desc()) \
                    .offset((page - 1) * page_size) \
                    .limit(page_size) \
                    .all()

                return {
                    "total": total,
                    "page": page,
                    "page_size": page_size,
                    "total_pages": (total + page_size - 1) // page_size,
                    "records": [
                        {
                            "id": r.id,
                            "timestamp": r.timestamp.isoformat() if r.timestamp else None,
                            "source": r.source,
                            "username": r.username,
                            "action": r.action,
                            "module": r.module,
                            "detail": r.detail,
                            "client_ip": r.client_ip,
                            "result": r.result,
                            "error_message": r.error_message,
                        }
                        for r in records
                    ]
                }

        except Exception as e:
            logger.error("查询审计日志失败: {}".format(e))
            return {"total": 0, "page": page, "page_size": page_size, "total_pages": 0, "records": []}

    def export_csv(self, source: str = None, username: str = None,
                   action: str = None, module: str = None,
                   start_time: datetime = None, end_time: datetime = None) -> str:
        """
        导出日志为CSV格式字符串

        Returns:
            CSV内容字符串
        """
        try:
            result = self.query(
                source=source, username=username, action=action,
                module=module, start_time=start_time, end_time=end_time,
                page=1, page_size=100000  # 大量导出
            )

            output = io.StringIO()
            writer = csv.writer(output)
            writer.writerow([
                "ID", "时间", "来源", "用户", "操作", "模块",
                "详情", "客户端IP", "结果", "错误信息"
            ])

            for r in result["records"]:
                writer.writerow([
                    r["id"],
                    r["timestamp"],
                    r["source"],
                    r["username"],
                    r["action"],
                    r["module"],
                    r["detail"],
                    r["client_ip"],
                    r["result"],
                    r["error_message"],
                ])

            return output.getvalue()

        except Exception as e:
            logger.error("导出审计日志失败: {}".format(e))
            return ""

    def get_statistics(self, days: int = 7) -> Dict:
        """获取日志统计信息"""
        try:
            with db_manager.get_session() as session:
                since = datetime.now() - timedelta(days=days)

                # 总数
                total = session.query(AuditLog).filter(
                    AuditLog.timestamp >= since
                ).count()

                # 按来源统计
                source_stats = {}
                for row in session.query(
                    AuditLog.source,
                    sqlalchemy.func.count(AuditLog.id)
                ).filter(AuditLog.timestamp >= since).group_by(AuditLog.source).all():
                    source_stats[row[0]] = row[1]

                # 按模块统计
                module_stats = {}
                for row in session.query(
                    AuditLog.module,
                    sqlalchemy.func.count(AuditLog.id)
                ).filter(AuditLog.timestamp >= since).group_by(AuditLog.module).all():
                    if row[0]:
                        module_stats[row[0]] = row[1]

                # 按用户统计
                user_stats = {}
                for row in session.query(
                    AuditLog.username,
                    sqlalchemy.func.count(AuditLog.id)
                ).filter(AuditLog.timestamp >= since).group_by(AuditLog.username).all():
                    user_stats[row[0]] = row[1]

                # 失败数
                failures = session.query(AuditLog).filter(
                    AuditLog.timestamp >= since,
                    AuditLog.result == "failure"
                ).count()

                # 最近操作
                recent = session.query(AuditLog).order_by(
                    AuditLog.timestamp.desc()
                ).limit(10).all()

                return {
                    "total": total,
                    "failures": failures,
                    "days": days,
                    "source_stats": source_stats,
                    "module_stats": module_stats,
                    "user_stats": user_stats,
                    "recent": [
                        {
                            "timestamp": r.timestamp.isoformat() if r.timestamp else None,
                            "source": r.source,
                            "username": r.username,
                            "action": r.action,
                            "module": r.module,
                            "detail": r.detail,
                            "result": r.result,
                        }
                        for r in recent
                    ]
                }

        except Exception as e:
            logger.error("获取日志统计失败: {}".format(e))
            return {"total": 0, "failures": 0, "days": days}

    def get_distinct_users(self) -> list:
        """获取审计日志中的所有不重复用户名"""
        try:
            with db_manager.get_session() as session:
                rows = session.query(
                    AuditLog.username
                ).distinct().order_by(AuditLog.username).all()
                return [row[0] for row in rows if row[0]]
        except Exception as e:
            logger.error("获取用户列表失败: {}".format(e))
            return []

    def cleanup(self, days: int = 90) -> Dict:
        """清理过期日志"""
        try:
            cutoff = datetime.now() - timedelta(days=days)
            with db_manager.get_session() as session:
                count = session.query(AuditLog).filter(
                    AuditLog.timestamp < cutoff
                ).count()

                if count > 0:
                    session.query(AuditLog).filter(
                        AuditLog.timestamp < cutoff
                    ).delete()
                    # 不需要手动 commit，get_session 上下文管理器会自动处理

            logger.info("已清理 {} 天前的审计日志，共 {} 条".format(days, count))
            return {"success": True, "message": "已清理 {} 条日志".format(count)}

        except Exception as e:
            logger.error("清理审计日志失败: {}".format(e))
            return {"success": False, "message": str(e)}


# ============================================================
# 便捷函数
# ============================================================

_audit_logger: Optional[AuditLogger] = None


def get_audit_logger() -> AuditLogger:
    """获取审计日志管理器单例"""
    global _audit_logger
    if _audit_logger is None:
        _audit_logger = AuditLogger()
    return _audit_logger


def log_web_action(action: str, module: str = "", detail: str = "",
                   result: str = "success", error_message: str = "",
                   request_data: dict = None):
    """Web操作日志记录（从Flask上下文获取用户和IP）"""
    try:
        from flask import request, session as flask_session
        from flask_login import current_user

        username = ""
        try:
            if current_user and current_user.is_authenticated:
                username = current_user.username
        except Exception:
            pass

        client_ip = ""
        user_agent = ""
        try:
            client_ip = request.remote_addr or ""
            user_agent = request.headers.get("User-Agent", "")
        except Exception:
            pass

        get_audit_logger().log(
            source="web",
            action=action,
            module=module,
            username=username,
            detail=detail,
            client_ip=client_ip,
            user_agent=user_agent,
            result=result,
            error_message=error_message,
            request_data=request_data,
        )
    except Exception as e:
        logger.debug("记录Web日志失败: {}".format(e))


def log_cli_action(action: str, module: str = "", detail: str = "",
                   username: str = "admin", result: str = "success"):
    """CLI操作日志记录"""
    get_audit_logger().log(
        source="cli",
        action=action,
        module=module,
        username=username,
        detail=detail,
        result=result,
    )


def audit_log(action: str, module: str = "", detail: str = ""):
    """
    装饰器：自动记录函数调用到审计日志
    
    用法:
        @audit_log(action="config_change", module="gateway")
        def some_function():
            ...
    """
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            result_val = "success"
            error_msg = ""
            try:
                return func(*args, **kwargs)
            except Exception as e:
                result_val = "failure"
                error_msg = str(e)
                raise
            finally:
                # 判断来源
                source = "cli"
                try:
                    from flask import has_request_context
                    if has_request_context():
                        source = "web"
                except ImportError:
                    pass

                get_audit_logger().log(
                    source=source,
                    action=action,
                    module=module,
                    detail=detail or func.__name__,
                    result=result_val,
                    error_message=error_msg,
                )
        return wrapper
    return decorator
