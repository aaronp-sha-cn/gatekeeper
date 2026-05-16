"""
GateKeeper - 双因素认证(2FA)模块
基于TOTP(RFC 6238)标准实现，使用Python标准库手动实现TOTP算法。
支持pyotp库（如果可用）作为备选。
"""

import os
import hmac
import hashlib
import base64
import struct
import time
import json
import secrets
import threading
from datetime import datetime
from typing import Optional, List, Dict, Any

from config.logging_config import get_logger
from config.logging_config import log_security_event
from core.database import db_manager

logger = get_logger("security.two_factor")


# ============================================================
# 尝试导入pyotp，如果不可用则使用手动实现
# ============================================================

try:
    import pyotp
    _HAS_PYOTP = True
    logger.debug("pyotp库可用，将使用pyotp进行TOTP计算")
except ImportError:
    _HAS_PYOTP = False
    logger.debug("pyotp库不可用，将使用手动TOTP实现")


# ============================================================
# TOTP配置数据类
# ============================================================

class TOTPConfig:
    """TOTP配置"""

    def __init__(self, id: int = None, user_id: int = None,
                 secret_key: str = "", enabled: bool = False,
                 backup_codes: List[str] = None,
                 created_at: datetime = None, last_used: datetime = None):
        self.id = id
        self.user_id = user_id
        self.secret_key = secret_key
        self.enabled = enabled
        self.backup_codes = backup_codes or []
        self.created_at = created_at
        self.last_used = last_used

    def to_dict(self) -> dict:
        """转换为字典（敏感字段脱敏）"""
        return {
            "id": self.id,
            "user_id": self.user_id,
            "secret_key": "***",
            "enabled": self.enabled,
            "backup_codes_count": len(self.backup_codes) if self.backup_codes else 0,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "last_used": self.last_used.isoformat() if self.last_used else None,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "TOTPConfig":
        """从字典创建"""
        created_at = None
        if data.get("created_at"):
            try:
                created_at = datetime.fromisoformat(data["created_at"])
            except (ValueError, TypeError):
                pass
        last_used = None
        if data.get("last_used"):
            try:
                last_used = datetime.fromisoformat(data["last_used"])
            except (ValueError, TypeError):
                pass
        return cls(
            id=data.get("id"),
            user_id=data.get("user_id"),
            secret_key=data.get("secret_key", ""),
            enabled=data.get("enabled", False),
            backup_codes=data.get("backup_codes", []),
            created_at=created_at,
            last_used=last_used,
        )


# ============================================================
# 双因素认证管理器
# ============================================================

class TwoFactorAuth:
    """双因素认证管理器"""

    # 临时令牌存储（生产环境应使用Redis等缓存）
    _temp_tokens: Dict[str, Dict] = {}

    def __init__(self):
        """初始化"""
        self._ensure_table()
        self._failed_attempts: Dict[int, Dict] = {}  # user_id -> {"count": int, "locked_at": float}
        self._max_failed_attempts = 10  # 最大失败次数
        self._lockout_duration = 300  # 锁定时长（秒）
        self._attempts_lock = threading.Lock()  # 线程安全锁
        logger.info("双因素认证模块初始化完成")

    def _ensure_table(self):
        """确保2FA数据表存在"""
        try:
            from config.database import engine
            from sqlalchemy import text, MetaData, Table, Column, Integer, String, Boolean, DateTime, Text

            metadata = MetaData()
            table = Table(
                "user_two_factor", metadata,
                Column("id", Integer, primary_key=True, autoincrement=True),
                Column("user_id", Integer, unique=True, nullable=False, index=True),
                Column("secret_key", String(256), nullable=False, default=""),
                Column("enabled", Boolean, nullable=False, default=False),
                Column("backup_codes", Text, nullable=True),
                Column("created_at", DateTime, nullable=True),
                Column("last_used", DateTime, nullable=True),
            )

            # 检查表是否存在，不存在则创建
            from sqlalchemy import inspect
            inspector = inspect(engine)
            if "user_two_factor" not in inspector.get_table_names():
                metadata.create_all(engine)
                logger.info("已创建 user_two_factor 表")
        except Exception as e:
            logger.warning("检查/创建2FA表失败: {}".format(e))

    # ============================================================
    # 密钥生成
    # ============================================================

    def generate_secret(self) -> str:
        """
        生成TOTP密钥（Base32编码）

        Returns:
            Base32编码的密钥字符串
        """
        if _HAS_PYOTP:
            secret = pyotp.random_base32()
        else:
            # 手动生成: 20字节随机数据，Base32编码
            secret = base64.b32encode(os.urandom(20)).decode("utf-8").rstrip("=")
        logger.debug("已生成新的TOTP密钥")
        return secret

    # ============================================================
    # TOTP URI 生成
    # ============================================================

    def get_totp_uri(self, username: str, secret: str, issuer: str = "GateKeeper") -> str:
        """
        生成 otpauth:// URI（用于QR码扫描）

        Args:
            username: 用户名
            secret: Base32密钥
            issuer: 发行方名称

        Returns:
            otpauth://totp/ URI字符串
        """
        import urllib.parse
        label = "{}:{}".format(issuer, username)
        params = urllib.parse.urlencode({
            "secret": secret,
            "issuer": issuer,
            "algorithm": "SHA1",
            "digits": "6",
            "period": "30",
        })
        uri = "otpauth://totp/{}?{}".format(urllib.parse.quote(label, safe=":"), params)
        return uri

    # ============================================================
    # TOTP 验证码生成与验证
    # ============================================================

    def verify_code(self, secret: str, code: str, valid_window: int = 1) -> bool:
        """
        验证TOTP验证码

        Args:
            secret: Base32密钥
            code: 用户输入的验证码
            valid_window: 允许的时间窗口偏移（前后各N个周期），默认1

        Returns:
            验证码是否正确
        """
        if not secret or not code:
            return False

        code = code.strip().replace(" ", "").replace("-", "")
        if len(code) != 6 or not code.isdigit():
            return False

        try:
            if _HAS_PYOTP:
                totp = pyotp.TOTP(secret)
                return totp.verify(code, valid_window=valid_window)
            else:
                return self._manual_verify(secret, code, valid_window)
        except Exception as e:
            logger.error("验证TOTP码失败: {}".format(e))
            return False

    def _time_code(self, timestamp: float = None, period: int = 30) -> int:
        """
        获取当前时间码（时间步长计数器）

        Args:
            timestamp: Unix时间戳，None表示当前时间
            period: 时间步长（秒）

        Returns:
            时间码（整数）
        """
        if timestamp is None:
            timestamp = time.time()
        return int(timestamp) // period

    def _generate_totp(self, secret: str, period: int = 30, digits: int = 6,
                       timestamp: float = None) -> str:
        """
        手动生成TOTP码（基于HMAC-SHA1，RFC 6238）

        Args:
            secret: Base32编码的密钥
            period: 时间步长（秒）
            digits: 验证码位数
            timestamp: Unix时间戳

        Returns:
            TOTP验证码字符串
        """
        if timestamp is None:
            timestamp = time.time()

        # Base32解码密钥
        # 补齐Base32填充
        secret_upper = secret.upper()
        padding = (8 - len(secret_upper) % 8) % 8
        secret_upper += "=" * padding
        try:
            key = base64.b32decode(secret_upper)
        except Exception:
            logger.error("Base32解码密钥失败")
            return ""

        # 计算时间码（8字节大端序）
        time_code = self._time_code(timestamp, period)
        time_bytes = struct.pack(">Q", time_code)

        # HMAC-SHA1
        hmac_hash = hmac.new(key, time_bytes, hashlib.sha1).digest()

        # 动态截断
        offset = hmac_hash[-1] & 0x0F
        binary = (
            ((hmac_hash[offset] & 0x7F) << 24) |
            ((hmac_hash[offset + 1] & 0xFF) << 16) |
            ((hmac_hash[offset + 2] & 0xFF) << 8) |
            (hmac_hash[offset + 3] & 0xFF)
        )
        code = binary % (10 ** digits)
        return str(code).zfill(digits)

    def _manual_verify(self, secret: str, code: str, valid_window: int = 1) -> bool:
        """
        手动验证TOTP码（带时间窗口）

        Args:
            secret: Base32密钥
            code: 验证码
            valid_window: 允许的时间窗口偏移

        Returns:
            是否验证通过
        """
        for offset in range(-valid_window, valid_window + 1):
            timestamp = time.time() + (offset * 30)
            generated = self._generate_totp(secret, timestamp=timestamp)
            if hmac.compare_digest(generated, code):
                return True
        return False

    # ============================================================
    # 备用恢复码
    # ============================================================

    def generate_backup_codes(self, count: int = 10) -> List[str]:
        """
        生成备用恢复码

        Args:
            count: 生成数量

        Returns:
            备用码列表（8位字母数字）
        """
        codes = []
        for _ in range(count):
            code = secrets.token_hex(4).upper()  # 8字符
            codes.append(code)
        logger.debug("已生成 {} 个备用恢复码".format(count))
        return codes

    def verify_backup_code(self, user_id: int, code: str) -> bool:
        """
        验证备用恢复码（一次性使用，验证后即失效）

        Args:
            user_id: 用户ID
            code: 备用码

        Returns:
            是否验证通过
        """
        if not code:
            return False

        code = code.strip().upper()
        config = self.get_user_2fa(user_id)
        if not config or not config.backup_codes:
            return False

        if code in config.backup_codes:
            # 移除已使用的备用码
            remaining_codes = [c for c in config.backup_codes if c != code]
            self._update_backup_codes(user_id, remaining_codes)
            log_security_event(
                user=str(user_id),
                action="2fa_backup_used",
                resource="two_factor",
                result="success",
                message="用户{}使用了备用恢复码".format(user_id)
            )
            logger.info("用户 {} 使用了备用恢复码".format(user_id))
            return True

        return False

    # ============================================================
    # 2FA 启用/禁用
    # ============================================================

    def enable_2fa(self, user_id: int, secret: str, backup_codes: List[str]) -> bool:
        """
        为用户启用2FA

        Args:
            user_id: 用户ID
            secret: TOTP密钥
            backup_codes: 备用恢复码列表

        Returns:
            是否启用成功
        """
        try:
            now = datetime.now()
            codes_json = json.dumps(backup_codes)

            with db_manager.get_session() as session:
                from sqlalchemy import text
                # 检查是否已有记录
                result = session.execute(
                    text("SELECT id FROM user_two_factor WHERE user_id = :uid"),
                    {"uid": user_id}
                ).fetchone()

                if result:
                    # 更新现有记录
                    session.execute(
                        text("""UPDATE user_two_factor
                                SET secret_key = :secret, enabled = 1,
                                    backup_codes = :codes, last_used = :now
                                WHERE user_id = :uid"""),
                        {"secret": secret, "codes": codes_json, "now": now, "uid": user_id}
                    )
                else:
                    # 插入新记录
                    session.execute(
                        text("""INSERT INTO user_two_factor
                                (user_id, secret_key, enabled, backup_codes, created_at, last_used)
                                VALUES (:uid, :secret, 1, :codes, :now, :now)"""),
                        {"uid": user_id, "secret": secret, "codes": codes_json, "now": now}
                    )

            log_security_event(
                user=str(user_id),
                action="2fa_enable",
                resource="two_factor",
                result="success",
                message="用户{}已启用双因素认证".format(user_id)
            )
            logger.info("用户 {} 已启用双因素认证".format(user_id))
            return True

        except Exception as e:
            logger.error("启用2FA失败: {}".format(e))
            log_security_event(
                user=str(user_id),
                action="2fa_enable",
                resource="two_factor",
                result="failure",
                message="启用2FA失败: {}".format(e)
            )
            return False

    def disable_2fa(self, user_id: int) -> bool:
        """
        禁用用户的2FA

        Args:
            user_id: 用户ID

        Returns:
            是否禁用成功
        """
        try:
            with db_manager.get_session() as session:
                from sqlalchemy import text
                session.execute(
                    text("DELETE FROM user_two_factor WHERE user_id = :uid"),
                    {"uid": user_id}
                )

            log_security_event(
                user=str(user_id),
                action="2fa_disable",
                resource="two_factor",
                result="success",
                message="用户{}已禁用双因素认证".format(user_id)
            )
            logger.info("用户 {} 已禁用双因素认证".format(user_id))
            return True

        except Exception as e:
            logger.error("禁用2FA失败: {}".format(e))
            log_security_event(
                user=str(user_id),
                action="2fa_disable",
                resource="two_factor",
                result="failure",
                message="禁用2FA失败: {}".format(e)
            )
            return False

    # ============================================================
    # 2FA 状态查询
    # ============================================================

    def get_user_2fa(self, user_id: int) -> Optional[TOTPConfig]:
        """
        获取用户2FA配置

        Args:
            user_id: 用户ID

        Returns:
            TOTPConfig对象或None
        """
        try:
            with db_manager.get_session() as session:
                from sqlalchemy import text
                row = session.execute(
                    text("""SELECT id, user_id, secret_key, enabled,
                                   backup_codes, created_at, last_used
                            FROM user_two_factor WHERE user_id = :uid"""),
                    {"uid": user_id}
                ).fetchone()

                if not row:
                    return None

                backup_codes = []
                if row[4]:
                    try:
                        backup_codes = json.loads(row[4])
                    except (json.JSONDecodeError, TypeError):
                        pass

                return TOTPConfig(
                    id=row[0],
                    user_id=row[1],
                    secret_key=row[2],
                    enabled=bool(row[3]),
                    backup_codes=backup_codes,
                    created_at=row[5],
                    last_used=row[6],
                )

        except Exception as e:
            logger.error("获取用户2FA配置失败: {}".format(e))
            return None

    def is_2fa_enabled(self, user_id: int) -> bool:
        """
        检查用户是否启用了2FA

        Args:
            user_id: 用户ID

        Returns:
            是否已启用
        """
        config = self.get_user_2fa(user_id)
        return config is not None and config.enabled

    # ============================================================
    # 登录验证
    # ============================================================

    def validate_login(self, user_id: int, code: str) -> bool:
        """
        验证登录时的2FA验证码

        Args:
            user_id: 用户ID
            code: TOTP验证码或备用恢复码

        Returns:
            是否验证通过
        """
        # 检查失败次数是否超过限制（线程安全）
        with self._attempts_lock:
            attempt_info = self._failed_attempts.get(user_id)
            if attempt_info and attempt_info["count"] >= self._max_failed_attempts:
                # 检查锁定是否已超时，超时则自动解除
                locked_at = attempt_info.get("locked_at", 0)
                if time.time() - locked_at > self._lockout_duration:
                    # 锁定时间已过，自动重置失败计数
                    self._failed_attempts.pop(user_id, None)
                    logger.info("用户 {} 2FA锁定已超时，自动解除锁定".format(user_id))
                else:
                    log_security_event(
                        user=str(user_id),
                        action="2fa_verify",
                        resource="two_factor",
                        result="locked",
                        message="用户{}2FA验证已锁定，失败次数过多".format(user_id)
                    )
                    return False

        config = self.get_user_2fa(user_id)
        if not config or not config.enabled:
            return False

        # 先尝试TOTP验证码
        if self.verify_code(config.secret_key, code):
            self._update_last_used(user_id)
            with self._attempts_lock:
                self._failed_attempts.pop(user_id, None)  # 验证成功，清除计数
            log_security_event(
                user=str(user_id),
                action="2fa_verify",
                resource="two_factor",
                result="success",
                message="用户{}2FA验证码验证成功".format(user_id)
            )
            return True

        # 再尝试备用恢复码
        if self.verify_backup_code(user_id, code):
            self._update_last_used(user_id)
            with self._attempts_lock:
                self._failed_attempts.pop(user_id, None)  # 验证成功，清除计数
            return True

        # 验证失败，递增计数（线程安全）
        with self._attempts_lock:
            attempt_info = self._failed_attempts.get(user_id, {"count": 0})
            new_count = attempt_info.get("count", 0) + 1
            self._failed_attempts[user_id] = {"count": new_count, "locked_at": time.time()}
            current_attempts = new_count
        log_security_event(
            user=str(user_id),
            action="2fa_verify",
            resource="two_factor",
            result="failure",
            message="用户{}2FA验证码错误({}/{})".format(user_id, current_attempts, self._max_failed_attempts)
        )
        return False

    # ============================================================
    # 临时令牌管理
    # ============================================================

    def create_temp_token(self, user_id: int, username: str) -> str:
        """
        创建临时令牌（登录成功后、2FA验证前使用）

        Args:
            user_id: 用户ID
            username: 用户名

        Returns:
            临时令牌字符串
        """
        token = secrets.token_urlsafe(32)
        self._temp_tokens[token] = {
            "user_id": user_id,
            "username": username,
            "created_at": time.time(),
        }
        # 5分钟后过期
        self._cleanup_temp_tokens()
        return token

    def verify_temp_token(self, token: str) -> Optional[Dict]:
        """
        验证临时令牌

        Args:
            token: 临时令牌

        Returns:
            令牌数据字典或None
        """
        data = self._temp_tokens.get(token)
        if not data:
            return None

        # 检查是否过期（5分钟）
        if time.time() - data["created_at"] > 300:
            del self._temp_tokens[token]
            return None

        return data

    def consume_temp_token(self, token: str) -> Optional[Dict]:
        """
        消费临时令牌（验证后删除）

        Args:
            token: 临时令牌

        Returns:
            令牌数据字典或None
        """
        data = self.verify_temp_token(token)
        if data:
            self._temp_tokens.pop(token, None)
        return data

    def _cleanup_temp_tokens(self):
        """清理过期的临时令牌"""
        now = time.time()
        expired = [k for k, v in self._temp_tokens.items()
                   if now - v["created_at"] > 300]
        for k in expired:
            del self._temp_tokens[k]

    # ============================================================
    # 备用码管理
    # ============================================================

    def regenerate_backup_codes(self, user_id: int) -> Optional[List[str]]:
        """
        重新生成备用恢复码

        Args:
            user_id: 用户ID

        Returns:
            新的备用码列表或None
        """
        config = self.get_user_2fa(user_id)
        if not config or not config.enabled:
            return None

        new_codes = self.generate_backup_codes(10)
        success = self._update_backup_codes(user_id, new_codes)
        if success:
            log_security_event(
                user=str(user_id),
                action="2fa_backup_regenerate",
                resource="two_factor",
                result="success",
                message="用户{}重新生成了备用恢复码".format(user_id)
            )
            return new_codes
        return None

    # ============================================================
    # 内部辅助方法
    # ============================================================

    def _update_last_used(self, user_id: int):
        """更新最后使用时间"""
        try:
            with db_manager.get_session() as session:
                from sqlalchemy import text
                session.execute(
                    text("UPDATE user_two_factor SET last_used = :now WHERE user_id = :uid"),
                    {"now": datetime.now(), "uid": user_id}
                )
        except Exception as e:
            logger.debug("更新2FA最后使用时间失败: {}".format(e))

    def _update_backup_codes(self, user_id: int, codes: List[str]) -> bool:
        """更新备用恢复码"""
        try:
            codes_json = json.dumps(codes)
            with db_manager.get_session() as session:
                from sqlalchemy import text
                session.execute(
                    text("UPDATE user_two_factor SET backup_codes = :codes WHERE user_id = :uid"),
                    {"codes": codes_json, "uid": user_id}
                )
            return True
        except Exception as e:
            logger.error("更新备用恢复码失败: {}".format(e))
            return False


# ============================================================
# 单例管理
# ============================================================

_two_factor_auth: Optional[TwoFactorAuth] = None
_two_factor_auth_lock = threading.Lock()


def get_two_factor_auth() -> TwoFactorAuth:
    """获取双因素认证管理器单例"""
    global _two_factor_auth
    if _two_factor_auth is None:
        with _two_factor_auth_lock:
            if _two_factor_auth is None:
                _two_factor_auth = TwoFactorAuth()
    return _two_factor_auth
