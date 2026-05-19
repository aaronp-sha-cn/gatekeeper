"""
GateKeeper - LDAP/Active Directory 身份认证提供者
实现 LDAP/AD 用户认证、组查询和用户同步功能
"""

import os
import json
import ssl
import threading
from datetime import datetime
from typing import Dict, List, Optional

from config.logging_config import get_logger

logger = get_logger("auth_ldap")

CONFIG_PATH = "/etc/gatekeeper/rules/auth_ldap.json"

# ldap3 库可能不可用，提供优雅降级
try:
    import ldap3
    from ldap3 import Server, Connection, ALL, SUBTREE
    from ldap3.core.exceptions import LDAPException, LDAPBindError, LDAPSocketOpenError
    _LDAP3_AVAILABLE = True
except ImportError:
    _LDAP3_AVAILABLE = False
    logger.warning("ldap3 库未安装，LDAP/AD 功能不可用。请执行: pip install ldap3")


class LDAPAuthProvider:
    """LDAP/AD 身份认证提供者"""

    def __init__(self):
        self._config = {
            "enabled": False,
            "server_url": "",           # ldap://server:389 或 ldaps://server:636
            "bind_dn": "",              # 管理员绑定 DN
            "bind_password": "",        # 管理员密码
            "user_base_dn": "",         # 用户搜索基础 DN
            "user_search_filter": "(sAMAccountName={username})",  # AD 格式
            "group_base_dn": "",        # 组搜索基础 DN
            "role_mapping": {           # 组到角色的映射
                "Domain Admins": "super_admin",
                "Security Admins": "admin",
                "Network Operators": "operator",
            },
            "use_ssl": True,
            "verify_cert": False,
            "auto_create_users": True,  # 首次登录自动创建本地用户
            "sync_interval": 3600,      # 用户同步间隔（秒）
        }
        self._connected = False
        self._stats = {
            "total_auth": 0,
            "auth_success": 0,
            "auth_failure": 0,
            "users_synced": 0,
            "last_sync": None,
        }
        self._lock = threading.RLock()
        self._load_config()

    # ---- 配置管理 ----

    def _load_config(self):
        """从配置文件加载配置"""
        try:
            if os.path.exists(CONFIG_PATH):
                with open(CONFIG_PATH, "r") as f:
                    saved = json.load(f)
                # 不覆盖密码字段（安全考虑）
                for key, value in saved.items():
                    if key != "bind_password":
                        self._config[key] = value
                # 显式加载密码
                if "bind_password" in saved:
                    self._config["bind_password"] = saved["bind_password"]
                logger.info("LDAP认证配置已加载")
        except Exception as e:
            logger.warning("加载LDAP认证配置失败: {}".format(e))

    def _save_config(self):
        """保存配置到文件"""
        try:
            os.makedirs(os.path.dirname(CONFIG_PATH), exist_ok=True)
            with open(CONFIG_PATH, "w") as f:
                json.dump(self._config, f, indent=2, ensure_ascii=False)
            # 设置文件权限（保护密码）
            os.chmod(CONFIG_PATH, 0o600)
        except Exception as e:
            logger.error("保存LDAP认证配置失败: {}".format(e))

    def configure(self, config: dict) -> dict:
        """更新配置"""
        try:
            with self._lock:
                for key, value in config.items():
                    if key in self._config:
                        self._config[key] = value
                self._save_config()
                logger.info("LDAP认证配置已更新")
                return {"status": "ok", "message": "配置已更新"}
        except Exception as e:
            logger.error("更新LDAP认证配置失败: {}".format(e))
            return {"status": "error", "message": str(e)}

    def get_config(self) -> dict:
        """获取配置（隐藏密码）"""
        with self._lock:
            config = dict(self._config)
            # 隐藏密码
            if config.get("bind_password"):
                config["bind_password"] = "********"
            return config

    # ---- 连接管理 ----

    def _check_available(self) -> dict:
        """检查 ldap3 是否可用"""
        if not _LDAP3_AVAILABLE:
            return {
                "status": "error",
                "message": "ldap3 库未安装。请执行: pip install ldap3",
            }
        return None

    def _get_connection(self, user_dn=None, password=None):
        """获取 LDAP 连接"""
        err = self._check_available()
        if err:
            return None, err

        try:
            server_url = self._config["server_url"]
            use_ssl = self._config["use_ssl"]
            verify_cert = self._config["verify_cert"]

            if not server_url:
                return None, {"status": "error", "message": "LDAP服务器地址未配置"}

            tls_config = None
            if use_ssl and not server_url.startswith("ldaps://"):
                # STARTTLS
                tls_config = ldap3.Tls(
                    validate=ssl.CERT_NONE if not verify_cert else ssl.CERT_REQUIRED,
                )

            server = Server(
                server_url,
                use_ssl=server_url.startswith("ldaps://"),
                get_info=ALL,
                tls=tls_config,
                connect_timeout=10,
            )

            bind_dn = user_dn or self._config["bind_dn"]
            bind_pw = password or self._config["bind_password"]

            if not bind_dn or not bind_pw:
                return None, {"status": "error", "message": "绑定DN或密码未配置"}

            conn = Connection(
                server,
                user=bind_dn,
                password=bind_pw,
                auto_bind=True,
                raise_exceptions=True,
            )
            return conn, None
        except LDAPBindError as e:
            return None, {"status": "error", "message": "LDAP绑定失败: 认证信息错误"}
        except LDAPSocketOpenError as e:
            return None, {"status": "error", "message": "无法连接到LDAP服务器: {}".format(str(e))}
        except LDAPException as e:
            return None, {"status": "error", "message": "LDAP错误: {}".format(str(e))}
        except Exception as e:
            return None, {"status": "error", "message": "连接异常: {}".format(str(e))}

    def test_connection(self) -> dict:
        """测试 LDAP 连接"""
        err = self._check_available()
        if err:
            return err

        try:
            conn, error = self._get_connection()
            if error:
                self._connected = False
                return error

            if conn and conn.bound:
                self._connected = True
                # 获取服务器信息
                server_info = str(conn.server.info) if conn.server.info else "unknown"
                conn.unbind()
                logger.info("LDAP连接测试成功")
                return {
                    "status": "ok",
                    "message": "连接成功",
                    "server_info": server_info[:200],
                }
            else:
                self._connected = False
                return {"status": "error", "message": "连接失败: 无法绑定"}
        except Exception as e:
            self._connected = False
            logger.error("LDAP连接测试失败: {}".format(e))
            return {"status": "error", "message": str(e)}

    # ---- 用户认证 ----

    @staticmethod
    def _escape_filter_chars(value: str) -> str:
        """转义LDAP搜索过滤器中的特殊字符，防止LDAP注入"""
        escape_map = {'\\': '\\5c', '*': '\\2a', '(': '\\28', ')': '\\29', '\x00': '\\00'}
        return ''.join(escape_map.get(c, c) for c in value)

    def authenticate(self, username: str, password: str) -> dict:
        """
        LDAP 用户认证

        1. 使用 bind_dn 绑定到 LDAP
        2. 搜索用户 (user_search_filter)
        3. 使用用户 DN 和密码尝试绑定
        4. 获取用户所属组
        5. 根据组映射确定角色
        6. 如果 auto_create_users，创建本地用户

        返回: {"success": bool, "username": str, "role": str, "groups": list, "error": str}
        """
        err = self._check_available()
        if err:
            return {"success": False, "username": username, "error": err["message"]}

        if not username or not password:
            return {"success": False, "username": username, "error": "用户名和密码不能为空"}

        try:
            with self._lock:
                self._stats["total_auth"] += 1

            # 1. 使用管理员账号绑定
            admin_conn, error = self._get_connection()
            if error:
                self._stats["auth_failure"] += 1
                return {"success": False, "username": username, "error": error["message"]}

            try:
                # 2. 搜索用户
                user_base_dn = self._config["user_base_dn"]
                if not user_base_dn:
                    self._stats["auth_failure"] += 1
                    return {"success": False, "username": username, "error": "用户搜索基础DN未配置"}

                search_filter = self._config["user_search_filter"].format(
                    username=self._escape_filter_chars(username)
                )

                admin_conn.search(
                    search_base=user_base_dn,
                    search_filter=search_filter,
                    search_scope=SUBTREE,
                    attributes=["cn", "mail", "memberOf", "distinguishedName"],
                )

                if not admin_conn.entries:
                    self._stats["auth_failure"] += 1
                    return {"success": False, "username": username, "error": "用户不存在"}

                user_entry = admin_conn.entries[0]
                user_dn = str(user_entry.distinguishedName)

                # 获取用户信息
                user_cn = ""
                user_mail = ""
                user_groups = []

                if "cn" in user_entry:
                    user_cn = str(user_entry.cn)
                if "mail" in user_entry:
                    user_mail = str(user_entry.mail)
                if "memberOf" in user_entry:
                    user_groups = [str(g) for g in user_entry.memberOf]

                # 3. 使用用户 DN 和密码尝试绑定（验证密码）
                user_conn, bind_error = self._get_connection(user_dn=user_dn, password=password)
                if bind_error:
                    self._stats["auth_failure"] += 1
                    return {"success": False, "username": username, "error": "密码错误"}

                user_conn.unbind()

                # 4. 根据组映射确定角色
                role = "VIEWER"  # 默认角色
                role_mapping = self._config.get("role_mapping", {})
                for group_dn in user_groups:
                    for group_name, mapped_role in role_mapping.items():
                        if group_name.lower() in group_dn.lower():
                            role = mapped_role
                            break

                # 5. 自动创建本地用户
                if self._config.get("auto_create_users", True):
                    self._auto_create_local_user(username, user_cn, user_mail, role)

                with self._lock:
                    self._stats["auth_success"] += 1

                logger.info("LDAP用户认证成功: {} (角色: {})".format(username, role))
                return {
                    "success": True,
                    "username": username,
                    "display_name": user_cn,
                    "email": user_mail,
                    "role": role,
                    "groups": user_groups,
                    "error": "",
                }
            except LDAPException as e:
                self._stats["auth_failure"] += 1
                return {"success": False, "username": username, "error": "LDAP错误: {}".format(str(e))}
            finally:
                try:
                    admin_conn.unbind()
                except Exception:
                    pass
        except Exception as e:
            self._stats["auth_failure"] += 1
            logger.error("LDAP用户认证异常: {}".format(e))
            return {"success": False, "username": username, "error": str(e)}

    def _auto_create_local_user(self, username, display_name, email, role):
        """自动创建本地用户"""
        try:
            from core.database import db_manager
            from core.models import User, UserRole

            with db_manager.get_session() as session:
                existing = session.query(User).filter_by(username=username).first()
                if existing:
                    # 更新角色
                    if role in [r.value for r in UserRole]:
                        existing.role = UserRole(role)
                    return

                # 创建新用户（设置随机密码，需要用户通过LDAP登录）
                import secrets
                random_password = secrets.token_hex(32)

                user = User(
                    username=username,
                    email=email or "",
                    password_hash=random_password,  # 临时密码，实际通过LDAP认证
                    role=UserRole(role) if role in [r.value for r in UserRole] else UserRole.VIEWER,
                    is_active=True,
                )
                session.add(user)
                logger.info("LDAP用户自动创建本地账户: {} (角色: {})".format(username, role))
        except Exception as e:
            logger.warning("自动创建本地用户失败: {}".format(e))

    # ---- 用户同步 ----

    def sync_users(self) -> dict:
        """从 LDAP 同步用户到本地数据库"""
        err = self._check_available()
        if err:
            return {"status": "error", "message": err["message"], "synced": 0}

        try:
            conn, error = self._get_connection()
            if error:
                return {"status": "error", "message": error["message"], "synced": 0}

            user_base_dn = self._config["user_base_dn"]
            if not user_base_dn:
                try:
                    conn.unbind()
                except Exception:
                    pass
                return {"status": "error", "message": "用户搜索基础DN未配置", "synced": 0}

            # 搜索所有用户
            conn.search(
                search_base=user_base_dn,
                search_filter="(objectClass=user)",
                search_scope=SUBTREE,
                attributes=["sAMAccountName", "cn", "mail", "memberOf"],
            )

            synced = 0
            created = 0
            updated = 0
            role_mapping = self._config.get("role_mapping", {})

            for entry in conn.entries:
                try:
                    username = str(entry.sAMAccountName) if "sAMAccountName" in entry else ""
                    if not username:
                        continue

                    display_name = str(entry.cn) if "cn" in entry else username
                    email = str(entry.mail) if "mail" in entry else ""
                    groups = []
                    if "memberOf" in entry:
                        groups = [str(g) for g in entry.memberOf]

                    # 确定角色
                    role = "VIEWER"
                    for group_dn in groups:
                        for group_name, mapped_role in role_mapping.items():
                            if group_name.lower() in group_dn.lower():
                                role = mapped_role
                                break

                    # 创建或更新本地用户
                    from core.database import db_manager
                    from core.models import User, UserRole

                    with db_manager.get_session() as session:
                        existing = session.query(User).filter_by(username=username).first()
                        if existing:
                            if role in [r.value for r in UserRole]:
                                existing.role = UserRole(role)
                            updated += 1
                        else:
                            import secrets
                            user = User(
                                username=username,
                                email=email,
                                password_hash=secrets.token_hex(32),
                                role=UserRole(role) if role in [r.value for r in UserRole] else UserRole.VIEWER,
                                is_active=True,
                            )
                            session.add(user)
                            created += 1

                    synced += 1
                except Exception as e:
                    logger.warning("同步用户失败: {}".format(e))
                    continue

            try:
                conn.unbind()
            except Exception:
                pass

            with self._lock:
                self._stats["users_synced"] = synced
                self._stats["last_sync"] = datetime.now().isoformat()

            logger.info("LDAP用户同步完成: {} 个用户 (新建: {}, 更新: {})".format(synced, created, updated))
            return {
                "status": "ok",
                "message": "同步完成",
                "synced": synced,
                "created": created,
                "updated": updated,
            }

        except Exception as e:
            logger.error("LDAP用户同步失败: {}".format(e))
            return {"status": "error", "message": str(e), "synced": 0}

    def get_user_groups(self, username: str) -> list:
        """获取用户所属组"""
        err = self._check_available()
        if err:
            return []

        try:
            conn, error = self._get_connection()
            if error:
                return []

            try:
                user_base_dn = self._config["user_base_dn"]
                if not user_base_dn:
                    conn.unbind()
                    return []

                search_filter = self._config["user_search_filter"].format(
                    username=self._escape_filter_chars(username)
                )
                conn.search(
                    search_base=user_base_dn,
                    search_filter=search_filter,
                    search_scope=SUBTREE,
                    attributes=["memberOf"],
                )

                groups = []
                if conn.entries:
                    entry = conn.entries[0]
                    if "memberOf" in entry:
                        groups = [str(g) for g in entry.memberOf]

                conn.unbind()
                return groups
            except Exception:
                try:
                    conn.unbind()
                except Exception:
                    pass
                return []
        except Exception:
            return []

    def get_stats(self) -> dict:
        """获取统计"""
        with self._lock:
            stats = dict(self._stats)
            stats["ldap3_available"] = _LDAP3_AVAILABLE
            stats["connected"] = self._connected
            stats["enabled"] = self._config["enabled"]
            stats["server_configured"] = bool(self._config.get("server_url"))
            return stats


# 全局单例
_ldap_auth_provider = None
_ldap_auth_provider_lock = threading.Lock()


def get_ldap_auth_provider() -> LDAPAuthProvider:
    """获取 LDAP 认证提供者单例"""
    global _ldap_auth_provider
    if _ldap_auth_provider is None:
        with _ldap_auth_provider_lock:
            if _ldap_auth_provider is None:
                _ldap_auth_provider = LDAPAuthProvider()
    return _ldap_auth_provider
