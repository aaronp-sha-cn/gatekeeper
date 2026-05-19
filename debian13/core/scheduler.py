"""
GateKeeper - 任务调度器
基于APScheduler的定时任务管理，负责流量分析、异常检测、漏洞扫描等周期性任务
"""

import threading
from datetime import datetime
from typing import Callable, Optional, Dict, Any

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger
from apscheduler.events import EVENT_JOB_ERROR, EVENT_JOB_MISSED, JobEvent
from apscheduler.jobstores.memory import MemoryJobStore
from apscheduler.executors.pool import ThreadPoolExecutor

from config.settings import settings
from config.logging_config import get_logger

logger = get_logger("scheduler")


# ============================================================
# 模块级任务函数（APScheduler SQLAlchemyJobStore 需要可序列化的函数引用）
# ============================================================

def _traffic_analysis_task():
    """流量分析定时任务"""
    from ai_engine.traffic_analyzer import TrafficAnalyzer
    analyzer = TrafficAnalyzer()
    analyzer.analyze_traffic_window()


def _anomaly_detection_task():
    """异常检测定时任务"""
    from ai_engine.anomaly_detector import AnomalyDetector
    detector = AnomalyDetector()
    detector.run_detection()


def _threat_intel_update_task():
    """威胁情报更新定时任务"""
    from ai_engine.threat_intelligence import ThreatIntelligenceManager
    intel_mgr = ThreatIntelligenceManager()
    intel_mgr.update_intelligence()


def _daily_report_task():
    """日报生成定时任务"""
    from reports.report_generator import ReportGenerator
    report_gen = ReportGenerator()
    report_gen.generate_daily_report()


def _try_get_sqlalchemy_jobstore(url: str):
    """
    Attempt to create a SQLAlchemyJobStore from the given database URL.
    Returns the jobstore on success, or None on failure.
    """
    try:
        from apscheduler.jobstores.sqlalchemy import SQLAlchemyJobStore
        # Test the connection by instantiating the store
        store = SQLAlchemyJobStore(url=url)
        return store
    except Exception as e:
        logger.warning(
            "无法创建 SQLAlchemyJobStore (url={}): {}, 回退到 MemoryJobStore".format(
                url, e
            )
        )
        return None


class TaskScheduler:
    """
    任务调度器
    管理所有定时任务的注册、启动和停止
    """

    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        """单例模式"""
        with cls._lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
                cls._instance._initialized = False
            return cls._instance

    def __init__(self):
        if self._initialized:
            return
        self._initialized = True
        self._scheduler = None
        self._jobs: Dict[str, str] = {}  # 任务名 -> 任务ID映射
        self._setup_scheduler()
        logger.info("任务调度器初始化完成")

    def _setup_scheduler(self):
        """配置并创建调度器"""
        # Try to use persistent SQLAlchemyJobStore when database is available
        persistent_store = None
        db_url = settings.database.url
        if settings.database.driver == "postgresql":
            # Convert SQLAlchemy URL to APScheduler-compatible format
            # e.g. postgresql+psycopg2:// -> postgresql://
            pscheduler_url = db_url.replace("+psycopg2", "")
            persistent_store = _try_get_sqlalchemy_jobstore(pscheduler_url)
        elif settings.database.driver == "sqlite":
            # For SQLite, use the database file path directly
            persistent_store = _try_get_sqlalchemy_jobstore("sqlite:///{}".format(
                settings.database.sqlite_path
            ))

        if persistent_store is not None:
            jobstores = {
                "default": persistent_store,
            }
            logger.info("调度器使用 SQLAlchemyJobStore (持久化存储)")
        else:
            jobstores = {
                "default": MemoryJobStore(),
            }
            logger.info("调度器使用 MemoryJobStore (非持久化存储)")
        executors = {
            "default": ThreadPoolExecutor(
                max_workers=settings.scheduler.max_workers
            ),
        }
        job_defaults = {
            "coalesce": True,       # 合并错过的任务
            "max_instances": 1,     # 每个任务最多一个实例
            "misfire_grace_time": 60,  # 错过任务的宽限时间（秒）
        }

        self._scheduler = BackgroundScheduler(
            jobstores=jobstores,
            executors=executors,
            job_defaults=job_defaults,
            timezone="Asia/Shanghai",
        )

        # 注册事件监听
        self._scheduler.add_listener(
            self._on_job_error, EVENT_JOB_ERROR
        )
        self._scheduler.add_listener(
            self._on_job_missed, EVENT_JOB_MISSED
        )

    def _on_job_error(self, event: JobEvent):
        """任务执行错误回调"""
        logger.error(
            "任务执行错误: job_id={}, exception={}".format(
                event.job_id, event.exception
            )
        )

    def _on_job_missed(self, event: JobEvent):
        """任务错过执行回调"""
        logger.warning(
            "任务错过执行: job_id={}, scheduled_time={}".format(
                event.job_id, event.scheduled_run_time
            )
        )

    def register_task(
        self,
        name: str,
        func: Callable,
        interval_seconds: int,
        start_now: bool = False,
        args: Optional[tuple] = None,
        kwargs: Optional[dict] = None,
    ) -> bool:
        """
        注册定时任务

        Args:
            name: 任务名称
            func: 任务函数
            interval_seconds: 执行间隔（秒）
            start_now: 是否立即执行一次
            args: 位置参数
            kwargs: 关键字参数

        Returns:
            是否注册成功
        """
        try:
            if name in self._jobs:
                logger.warning("任务 '{}' 已存在，将先移除旧任务".format(name))
                self.remove_task(name)

            job = self._scheduler.add_job(
                func=func,
                trigger=IntervalTrigger(seconds=interval_seconds),
                id=name,
                name=name,
                args=args or (),
                kwargs=kwargs or {},
                replace_existing=True,
            )
            self._jobs[name] = job.id
            logger.info(
                "注册任务: name='{}', interval={}s, job_id={}".format(
                    name, interval_seconds, job.id
                )
            )

            if start_now:
                func(*(args or ()), **(kwargs or {}))

            return True
        except Exception as e:
            logger.error("注册任务失败: name='{}', error={}".format(name, e))
            return False

    def remove_task(self, name: str) -> bool:
        """
        移除定时任务

        Args:
            name: 任务名称

        Returns:
            是否移除成功
        """
        try:
            if name in self._jobs:
                self._scheduler.remove_job(self._jobs[name])
                del self._jobs[name]
                logger.info("移除任务: name='{}'".format(name))
                return True
            logger.warning("任务 '{}' 不存在".format(name))
            return False
        except Exception as e:
            logger.error("移除任务失败: name='{}', error={}".format(name, e))
            return False

    def pause_task(self, name: str) -> bool:
        """暂停任务"""
        try:
            if name in self._jobs:
                self._scheduler.pause_job(self._jobs[name])
                logger.info("暂停任务: name='{}'".format(name))
                return True
            return False
        except Exception as e:
            logger.error("暂停任务失败: name='{}', error={}".format(name, e))
            return False

    def resume_task(self, name: str) -> bool:
        """恢复任务"""
        try:
            if name in self._jobs:
                self._scheduler.resume_job(self._jobs[name])
                logger.info("恢复任务: name='{}'".format(name))
                return True
            return False
        except Exception as e:
            logger.error("恢复任务失败: name='{}', error={}".format(name, e))
            return False

    def run_task_now(self, name: str) -> bool:
        """立即执行任务"""
        try:
            if name in self._jobs:
                self._scheduler.modify_job(self._jobs[name], next_run_time=datetime.now())
                logger.info("立即执行任务: name='{}'".format(name))
                return True
            return False
        except Exception as e:
            logger.error("立即执行任务失败: name='{}', error={}".format(name, e))
            return False

    def get_task_info(self, name: str) -> Optional[Dict[str, Any]]:
        """获取任务信息"""
        if name in self._jobs:
            job = self._scheduler.get_job(self._jobs[name])
            if job:
                return {
                    "id": job.id,
                    "name": job.name,
                    "next_run_time": str(job.next_run_time),
                    "trigger": str(job.trigger),
                }
        return None

    def list_tasks(self) -> Dict[str, Dict[str, Any]]:
        """列出所有已注册的任务"""
        tasks = {}
        for name, job_id in self._jobs.items():
            job = self._scheduler.get_job(job_id)
            if job:
                tasks[name] = {
                    "id": job.id,
                    "name": job.name,
                    "next_run_time": str(job.next_run_time),
                    "trigger": str(job.trigger),
                }
        return tasks

    def start(self):
        """启动调度器"""
        if not self._scheduler.running:
            self._scheduler.start()
            logger.info("任务调度器已启动")

    def stop(self, wait: bool = True):
        """停止调度器"""
        if self._scheduler.running:
            self._scheduler.shutdown(wait=wait)
            logger.info("任务调度器已停止")

    @property
    def is_running(self) -> bool:
        """调度器是否正在运行"""
        return self._scheduler.running if self._scheduler else False

    def register_default_tasks(self):
        """
        注册默认的定时任务
        包括流量分析、异常检测、漏洞扫描、威胁情报更新等
        """
        # 如果任务已注册，跳过
        if self._scheduler.get_job("traffic_analysis"):
            logger.info("默认任务已注册，跳过重复创建")
            return

        # 使用模块级函数（定义在文件顶部），确保APScheduler可以序列化
        # 流量分析任务
        self.register_task(
            name="traffic_analysis",
            func=_traffic_analysis_task,
            interval_seconds=settings.scheduler.traffic_analysis_interval,
        )

        # 异常检测任务
        self.register_task(
            name="anomaly_detection",
            func=_anomaly_detection_task,
            interval_seconds=settings.scheduler.anomaly_detection_interval,
        )

        # 威胁情报更新
        self.register_task(
            name="threat_intel_update",
            func=_threat_intel_update_task,
            interval_seconds=settings.scheduler.threat_intel_interval,
        )

        # 报表生成
        self.register_task(
            name="daily_report",
            func=_daily_report_task,
            interval_seconds=settings.scheduler.report_interval,
        )

        logger.info("默认定时任务注册完成")


# 全局调度器实例
task_scheduler = TaskScheduler()
