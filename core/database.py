"""
GateKeeper - 数据库管理器
提供数据库连接管理、会话管理和常用数据库操作
"""

import threading
from typing import Optional, Any, List, Type, TypeVar
from contextlib import contextmanager

from sqlalchemy import text
from sqlalchemy.orm import Session

from config.settings import settings
from config.database import engine, SessionLocal, Base
from config.logging_config import get_logger

logger = get_logger("database")

T = TypeVar("T")


class DatabaseManager:
    """
    数据库管理器
    封装数据库连接、会话管理和常用操作
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
        self._engine = engine
        self._session_factory = SessionLocal
        logger.info("数据库管理器初始化完成")

    @contextmanager
    def get_session(self) -> Session:
        """
        获取数据库会话的上下文管理器
        自动处理提交和回滚

        用法:
            with db_manager.get_session() as session:
                user = session.query(User).first()
        """
        session = self._session_factory()
        try:
            yield session
            session.commit()
        except Exception as e:
            session.rollback()
            logger.error("数据库操作失败，已回滚: {}".format(e))
            raise
        finally:
            session.close()

    def execute_raw(self, sql: str, params: Optional[dict] = None) -> Any:
        """
        执行原始SQL语句

        Args:
            sql: SQL语句
            params: 查询参数

        Returns:
            查询结果（已转换为列表，避免session关闭后访问问题）
        """
        with self.get_session() as session:
            result = session.execute(text(sql), params or {})
            # 立即获取所有数据，避免session关闭后result无法访问
            return list(result)

    def add(self, obj) -> Any:
        """
        添加单个对象到数据库

        Args:
            obj: ORM模型实例

        Returns:
            添加后的对象（含ID）
        """
        with self.get_session() as session:
            session.add(obj)
            session.flush()
            session.refresh(obj)
            return obj

    def add_all(self, objects: List) -> List:
        """
        批量添加对象到数据库

        Args:
            objects: ORM模型实例列表

        Returns:
            添加后的对象列表
        """
        with self.get_session() as session:
            session.add_all(objects)
            session.flush()
            for obj in objects:
                session.refresh(obj)
            return objects

    def get_by_id(self, model: Type[T], obj_id: int) -> Optional[T]:
        """
        根据ID获取对象

        Args:
            model: ORM模型类
            obj_id: 对象ID

        Returns:
            模型实例或None
        """
        with self.get_session() as session:
            return session.query(model).filter_by(id=obj_id).first()

    def get_all(self, model: Type[T], limit: int = 100, offset: int = 0) -> List[T]:
        """
        获取所有对象（分页）

        Args:
            model: ORM模型类
            limit: 每页数量
            offset: 偏移量

        Returns:
            模型实例列表
        """
        with self.get_session() as session:
            return session.query(model).offset(offset).limit(limit).all()

    def delete(self, model: Type[T], obj_id: int) -> bool:
        """
        根据ID删除对象

        Args:
            model: ORM模型类
            obj_id: 对象ID

        Returns:
            是否删除成功
        """
        with self.get_session() as session:
            obj = session.query(model).filter_by(id=obj_id).first()
            if obj:
                session.delete(obj)
                return True
            return False

    def count(self, model: Type[T]) -> int:
        """
        统计模型记录数

        Args:
            model: ORM模型类

        Returns:
            记录总数
        """
        with self.get_session() as session:
            return session.query(model).count()

    def check_health(self) -> dict:
        """
        检查数据库健康状态

        Returns:
            包含健康信息的字典
        """
        health_info = {
            "status": "healthy",
            "driver": settings.database.driver,
        }
        try:
            with self._engine.connect() as conn:
                if settings.database.driver == "sqlite":
                    result = conn.execute(text("SELECT 1"))
                else:
                    result = conn.execute(text("SELECT 1"))
                result.fetchone()
                health_info["connection"] = "ok"
        except Exception as e:
            health_info["status"] = "unhealthy"
            health_info["connection"] = "error: {}".format(str(e))
            logger.error("数据库健康检查失败: {}".format(e))

        return health_info

    def get_table_sizes(self) -> dict:
        """
        获取各表的记录数

        Returns:
            表名到记录数的映射
        """
        sizes = {}
        try:
            with self._engine.connect() as conn:
                for table_name in Base.metadata.tables:
                    result = conn.execute(
                        text("SELECT COUNT(*) FROM {}".format(table_name))
                    )
                    count = result.scalar()
                    sizes[table_name] = count
        except Exception as e:
            logger.error("获取表大小失败: {}".format(e))
        return sizes


# 全局数据库管理器实例
db_manager = DatabaseManager()
