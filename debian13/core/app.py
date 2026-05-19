"""
GateKeeper - 应用入口
主应用类 GateKeeper，管理所有子系统的启动、停止和协调
"""

import signal
import sys
import os
import time
import threading
import traceback as tb

from config.settings import settings, DATA_DIR
from config.logging_config import get_logger, log_security_event

logger = get_logger("app")

# 延迟导入的模块缓存（避免重复导入）
_lazy_modules = {}


def _lazy_import(module_path, attr_names=None):
    """延迟导入模块，带缓存和异常保护。
    
    Args:
        module_path: 模块路径，如 'config.database'
        attr_names: 需要从模块中获取的属性名列表
    
    Returns:
        如果指定了 attr_names，返回属性元组；否则返回模块对象
        导入失败时返回 None 或 (None, None, ...)
    """
    cache_key = module_path
    if cache_key in _lazy_modules:
        mod = _lazy_modules[cache_key]
    else:
        try:
            mod = __import__(module_path, fromlist=attr_names or [""])
            _lazy_modules[cache_key] = mod
        except Exception as e:
            logger.error("导入模块 '{}' 失败: {}".format(module_path, e))
            _lazy_modules[cache_key] = None
            mod = None
    
    if mod is None:
        if attr_names:
            return tuple(None for _ in attr_names)
        return None
    
    if attr_names:
        return tuple(getattr(mod, name, None) for name in attr_names)
    return mod


class GateKeeper:
    """
    GateKeeper 主应用类
    统一管理所有子系统的生命周期
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

        self._running = False
        self._components = {}

        # 注册信号处理
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)

        logger.info(
            "GateKeeper v{} 初始化中...".format(settings.version)
        )

    def _signal_handler(self, signum, frame):
        """信号处理函数，优雅关闭"""
        sig_name = signal.Signals(signum).name
        logger.info("收到信号 {}，正在关闭系统...".format(sig_name))
        self.stop()

    def initialize(self) -> bool:
        """
        初始化所有子系统
        按顺序初始化: 数据库 -> AI引擎 -> 网络模块 -> 告警系统 -> Web服务

        Returns:
            是否初始化成功
        """
        logger.info("=" * 60)
        logger.info("  GateKeeper 系统初始化")
        logger.info("=" * 60)

        # 1. 初始化数据库
        logger.info("[1/7] 初始化数据库...")
        try:
            init_db, check_connection = _lazy_import("config.database", ["init_db", "check_connection"])
            if init_db is None:
                logger.error("  数据库模块导入失败")
                return False
            init_db()
            ok, msg = check_connection()
            if ok:
                logger.info("  数据库: {}".format(msg))
            else:
                logger.error("  数据库: {}".format(msg))
                return False
        except Exception as e:
            logger.error("  数据库初始化失败: {}".format(e))
            return False

        # 2. 初始化AI引擎
        logger.info("[2/7] 初始化AI引擎...")
        try:
            ModelManager = _lazy_import("ai_engine.model_manager", ["ModelManager"])[0]
            if ModelManager is None:
                logger.warning("  AI引擎模块导入失败（将使用默认模型）")
            else:
                model_manager = ModelManager()
                model_manager.load_models()
                self._components["model_manager"] = model_manager
                logger.info("  AI引擎: 模型加载完成")
        except Exception as e:
            logger.warning("  AI引擎初始化警告（将使用默认模型）: {}".format(e))

        # 3. 初始化网络模块
        logger.info("[3/7] 初始化网络模块...")
        try:
            PacketCapture = _lazy_import("network.packet_capture", ["PacketCapture"])[0]
            FirewallManager = _lazy_import("network.firewall", ["FirewallManager"])[0]
            if PacketCapture is None or FirewallManager is None:
                logger.warning("  网络模块导入失败")
            else:
                packet_capture = PacketCapture()
                firewall_mgr = FirewallManager()
                self._components["packet_capture"] = packet_capture
                self._components["firewall"] = firewall_mgr

                # 初始化流量分析器并注册为数据包捕获回调
                TrafficAnalyzer = _lazy_import("ai_engine.traffic_analyzer", ["TrafficAnalyzer"])[0]
                if TrafficAnalyzer is not None:
                    traffic_analyzer = TrafficAnalyzer()
                    packet_capture.register_callback(traffic_analyzer.process_packet)
                    self._components["traffic_analyzer"] = traffic_analyzer
                logger.info(
                    "  网络模块: 监听接口={}, 流量分析器已注册".format(settings.network.listen_interface)
                )
        except Exception as e:
            logger.warning("  网络模块初始化警告: {}".format(e))

        # 4. 初始化告警系统
        logger.info("[4/7] 初始化告警系统...")
        try:
            AlertManager = _lazy_import("alerting.alert_manager", ["AlertManager"])[0]
            if AlertManager is None:
                logger.warning("  告警系统模块导入失败")
            else:
                alert_mgr = AlertManager()
                self._components["alert_manager"] = alert_mgr
                logger.info("  告警系统: 初始化完成")
        except Exception as e:
            logger.warning("  告警系统初始化警告: {}".format(e))

        # 5. 初始化IDS引擎
        logger.info("[5/7] 初始化IDS入侵检测引擎...")
        try:
            ids_mod = _lazy_import("security.ids_engine", ["get_ids_engine"])
            get_ids_engine = ids_mod[0] if ids_mod else None
            if get_ids_engine is None:
                logger.warning("  IDS引擎模块导入失败")
            else:
                ids_engine = get_ids_engine()
                ids_engine.start()
                self._components["ids_engine"] = ids_engine
                logger.info("  IDS引擎: 已启动")
        except Exception as e:
            logger.warning("  IDS引擎初始化警告: {}".format(e))

        # 6. 初始化任务调度器
        logger.info("[6/7] 初始化任务调度器...")
        try:
            task_scheduler_mod = _lazy_import("core.scheduler", ["task_scheduler"])
            task_scheduler = task_scheduler_mod[0] if task_scheduler_mod else None
            if task_scheduler is None:
                logger.warning("  任务调度器模块导入失败")
            else:
                task_scheduler.register_default_tasks()
                self._components["scheduler"] = task_scheduler
                logger.info("  任务调度器: 默认任务注册完成")
        except Exception as e:
            logger.warning("  任务调度器初始化警告: {}".format(e))

        # 7. 创建默认管理员用户
        logger.info("[7/7] 创建默认管理员...")
        try:
            self._create_default_admin()
        except Exception as e:
            logger.warning("  创建默认管理员警告: {}".format(e))

        logger.info("=" * 60)
        logger.info("  系统初始化完成")
        logger.info("=" * 60)
        return True

    def _create_default_admin(self):
        """创建默认用户：超级管理员(admin-sp)和管理员(admin)
        
        首次创建时自动生成随机密码（仅当环境变量未设置时）。
        已存在的用户不会被覆盖密码。
        随机密码写入 /opt/gatekeeper/.initial_credentials 文件。
        
        环境变量（可选，用于自定义初始密码）:
          - GK_ADMIN_SP_PASSWORD: 超级管理员密码
          - GK_ADMIN_PASSWORD: 管理员密码
        """
        import secrets as _secrets
        from core.models import User, UserRole
        from utils.crypto import hash_password

        # 密码来源优先级：环境变量 > 随机生成
        def _get_password(env_key: str) -> str:
            env_val = os.environ.get(env_key)
            if env_val:
                return env_val
            # 生成16位随机密码，包含大小写字母、数字和特殊字符
            alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@%&*"
            while True:
                pwd = ''.join(_secrets.choice(alphabet) for _ in range(16))
                # 确保至少包含大写、小写、数字、特殊字符各一个
                if (any(c.islower() for c in pwd) and any(c.isupper() for c in pwd) and
                    any(c.isdigit() for c in pwd) and any(c in '!@%&*' for c in pwd)):
                    return pwd

        def _write_credentials(username: str, password: str):
            """将凭据追加写入 .initial_credentials 文件"""
            cred_file = os.path.join(str(DATA_DIR), ".initial_credentials")
            try:
                with open(cred_file, "a") as f:
                    f.write("{}:{}\n".format(username, password))
                os.chmod(cred_file, 0o600)
            except Exception as e:
                logger.warning("  写入凭据文件失败: {}".format(e))

        with _lazy_import("core.database", ["db_manager"])[0].get_session() as session:
            # 超级管理员账号
            sp = session.query(User).filter_by(username="admin-sp").first()
            if not sp:
                sp_password = _get_password("GK_ADMIN_SP_PASSWORD")
                sp = User(
                    username="admin-sp",
                    email="admin-sp@gatekeeper.local",
                    password_hash=hash_password(sp_password),
                    role=UserRole.SUPER_ADMIN,
                    is_active=True,
                    must_change_password=True,
                )
                session.add(sp)
                # 将密码写入凭据文件
                _write_credentials("admin-sp", sp_password)
                logger.info("  默认超级管理员已创建 (admin-sp)")
                logger.info("  admin-sp 密码已写入 /opt/gatekeeper/.initial_credentials")
            else:
                # 修复枚举比较：处理数据库中存储的小写字符串值
                current_role = sp.role.value if hasattr(sp.role, 'value') else sp.role
                if current_role != UserRole.SUPER_ADMIN.value:
                    sp.role = UserRole.SUPER_ADMIN
                    logger.info("  admin-sp 已升级为超级管理员")
                else:
                    logger.info("  默认超级管理员已存在")

                # 仅当用户尚未修改过密码时（must_change_password=True），
                # 才从环境变量更新密码，防止重启后覆盖用户已修改的密码
                env_sp_password = os.environ.get("GK_ADMIN_SP_PASSWORD")
                if env_sp_password and getattr(sp, 'must_change_password', False):
                    sp.password_hash = hash_password(env_sp_password)
                    sp.must_change_password = True
                    _write_credentials("admin-sp", env_sp_password)
                    logger.info("  admin-sp 密码已从环境变量更新")
                elif env_sp_password and not getattr(sp, 'must_change_password', False):
                    # 用户已修改过密码，清除环境变量文件防止后续重启干扰
                    logger.info("  admin-sp 密码已被用户修改，跳过环境变量密码")

            # 普通管理员账号
            admin = session.query(User).filter_by(username="admin").first()
            if not admin:
                admin_password = _get_password("GK_ADMIN_PASSWORD")
                admin = User(
                    username="admin",
                    email="admin@gatekeeper.local",
                    password_hash=hash_password(admin_password),
                    role=UserRole.ADMIN,
                    is_active=True,
                    must_change_password=True,
                )
                session.add(admin)
                # 将密码写入凭据文件
                _write_credentials("admin", admin_password)
                logger.info("  默认管理员已创建 (admin)")
                logger.info("  admin 密码已写入 /opt/gatekeeper/.initial_credentials")
            else:
                # 修复枚举比较：处理数据库中存储的小写字符串值
                current_role = admin.role.value if hasattr(admin.role, 'value') else admin.role
                if current_role == UserRole.SUPER_ADMIN.value:
                    admin.role = UserRole.ADMIN
                    logger.info("  admin 角色已调整为管理员")

                # 仅当用户尚未修改过密码时（must_change_password=True），
                # 才从环境变量更新密码，防止重启后覆盖用户已修改的密码
                env_admin_password = os.environ.get("GK_ADMIN_PASSWORD")
                if env_admin_password and getattr(admin, 'must_change_password', False):
                    admin.password_hash = hash_password(env_admin_password)
                    admin.must_change_password = True
                    _write_credentials("admin", env_admin_password)
                    logger.info("  admin 密码已从环境变量更新")
                elif env_admin_password and not getattr(admin, 'must_change_password', False):
                    logger.info("  admin 密码已被用户修改，跳过环境变量密码")
                else:
                    logger.info("  默认管理员已存在")

    def start(self, enable_web: bool = True, enable_capture: bool = False):
        """
        启动所有子系统

        Args:
            enable_web: 是否启动Web管理面板
            enable_capture: 是否启动数据包捕获
        """
        if self._running:
            logger.warning("系统已在运行中")
            return

        logger.info("正在启动 GateKeeper 系统...")

        # 启动任务调度器
        scheduler = self._components.get("scheduler")
        if scheduler:
            scheduler.start()
            logger.info("任务调度器已启动")
        else:
            logger.warning("任务调度器不可用，跳过启动")

        # 启动数据包捕获
        if enable_capture:
            capture = self._components.get("packet_capture")
            if capture:
                try:
                    capture.start_capture(
                        interface=settings.network.listen_interface,
                        bpf_filter=settings.network.bpf_filter,
                    )
                    logger.info("数据包捕获已启动")
                except Exception as e:
                    logger.error("数据包捕获启动失败: {}".format(e))

        # 启动Web服务
        if enable_web:
            self._running = True  # 先标记运行，使端口检测循环能正常工作
            self._start_web_server()
        else:
            self._running = True
        logger.info("GateKeeper 系统启动完成")
        log_security_event(
            user="system",
            action="system_start",
            resource="gatekeeper",
            result="success",
            message="GateKeeper 系统启动"
        )

    def _start_web_server(self):
        """启动Web管理面板（在独立线程中）

        SSL证书管理:
          - 生产环境建议使用 Let's Encrypt 证书，运行 scripts/cert-manager.sh obtain
          - 自签名证书会在首次启动时自动生成
          - 证书自动续签: scripts/cert-manager.sh cron-install
          - 详见 scripts/cert-manager.sh help
        """
        import socket
        import traceback as tb

        self._web_started = False
        protocol = "http"  # 默认协议，防止SSL证书生成失败时变量未定义

        def run_web():
            try:
                logger.info("正在创建Flask应用...")
                import sys
                sys.stdout.flush()
                sys.stderr.flush()
                from web.app import create_web_app
                app = create_web_app()
                logger.info("Flask应用创建成功")
                sys.stdout.flush()
            except Exception as e:
                logger.error("创建Flask应用失败: {}".format(e))
                logger.error(tb.format_exc())
                import sys
                sys.stdout.flush()
                sys.stderr.flush()
                return

            ssl_context = None
            if settings.web.ssl_enabled:
                cert_dir = os.path.dirname(settings.web.ssl_cert)
                os.makedirs(cert_dir, exist_ok=True)
                if os.path.exists(settings.web.ssl_cert) and os.path.exists(settings.web.ssl_key):
                    ssl_context = (
                        settings.web.ssl_cert,
                        settings.web.ssl_key,
                    )
                    logger.info("使用已有SSL证书")
                else:
                    logger.info("SSL证书不存在，自动生成自签名证书...")
                    try:
                        from cryptography import x509
                        from cryptography.x509.oid import NameOID
                        from cryptography.hazmat.primitives import hashes, serialization
                        from cryptography.hazmat.primitives.asymmetric import rsa
                        import datetime as dt

                        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
                        subject = issuer = x509.Name([
                            x509.NameAttribute(NameOID.COUNTRY_NAME, "CN"),
                            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Beijing"),
                            x509.NameAttribute(NameOID.LOCALITY_NAME, "Beijing"),
                            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "GateKeeper"),
                            x509.NameAttribute(NameOID.COMMON_NAME, "GateKeeper"),
                        ])
                        now_utc = dt.datetime.now(dt.timezone.utc)
                        cert = (
                            x509.CertificateBuilder()
                            .subject_name(subject)
                            .issuer_name(issuer)
                            .public_key(key.public_key())
                            .serial_number(x509.random_serial_number())
                            .not_valid_before(now_utc)
                            .not_valid_after(now_utc + dt.timedelta(days=3650))
                            .sign(key, hashes.SHA256())
                        )
                        with open(settings.web.ssl_cert, "wb") as f:
                            f.write(cert.public_bytes(serialization.Encoding.PEM))
                        with open(settings.web.ssl_key, "wb") as f:
                            f.write(key.private_bytes(
                                serialization.Encoding.PEM,
                                serialization.PrivateFormat.TraditionalOpenSSL,
                                serialization.NoEncryption(),
                            ))
                        ssl_context = (settings.web.ssl_cert, settings.web.ssl_key)
                        logger.info("自签名SSL证书已生成")
                    except Exception as e:
                        logger.warning("SSL证书生成失败，降级为HTTP模式: {}".format(e))
                        ssl_context = None

            protocol = "https" if ssl_context else "http"
            listen_port = settings.web.port
            logger.info("正在启动Web服务器: {}://{}:{}".format(protocol, settings.web.host, listen_port))

            try:
                logger.info("正在启动Web服务器: {}://{}:{}".format(protocol, settings.web.host, listen_port))
                app.run(
                    host=settings.web.host,
                    port=listen_port,
                    debug=False,
                    ssl_context=ssl_context,
                    threaded=True,
                    use_reloader=False,
                )
                logger.info("Web服务器已正常停止")
            except Exception as e:
                logger.error("Web服务器运行异常: {}".format(e))
                logger.error(tb.format_exc())

        web_thread = threading.Thread(
            target=run_web,
            name="web-server",
            daemon=False,
        )
        web_thread.start()
        self._components["web_thread"] = web_thread

        # 等待端口就绪
        for i in range(30):
            if not self._running:
                break
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                # 连接 127.0.0.1 而不是 0.0.0.0
                result = sock.connect_ex(("127.0.0.1", settings.web.port))
                sock.close()
                if result == 0:
                    self._web_started = True
                    logger.info(
                        "Web管理面板已启动: {}://127.0.0.1:{}".format(protocol, settings.web.port)
                    )
                    break
            except Exception:
                pass
            time.sleep(1)
        else:
            logger.warning("Web服务启动超时（30秒），请检查日志")

    def stop(self):
        """停止所有子系统"""
        if not self._running:
            return

        logger.info("正在停止 GateKeeper 系统...")

        # 停止数据包捕获
        capture = self._components.get("packet_capture")
        if capture:
            try:
                capture.stop_capture()
                logger.info("数据包捕获已停止")
            except Exception as e:
                logger.error("停止数据包捕获失败: {}".format(e))

        # 停止IDS引擎
        ids_engine = self._components.get("ids_engine")
        if ids_engine:
            try:
                ids_engine.stop()
                logger.info("IDS引擎已停止")
            except Exception as e:
                logger.error("停止IDS引擎失败: {}".format(e))

        # 停止任务调度器
        scheduler = self._components.get("scheduler")
        if scheduler:
            scheduler.stop()
            logger.info("任务调度器已停止")

        # 保存AI模型状态
        model_mgr = self._components.get("model_manager")
        if model_mgr:
            try:
                model_mgr.save_models()
                logger.info("AI模型状态已保存")
            except Exception as e:
                logger.error("保存AI模型失败: {}".format(e))

        self._running = False

        # 关闭 Web 服务器线程
        web_thread = self._components.get("web_thread")
        if web_thread and web_thread.is_alive():
            import requests as _req
            try:
                if settings.web.ssl_enabled:
                    _req.post("https://127.0.0.1:{}/shutdown".format(settings.web.port), timeout=5, verify=False)
                else:
                    _req.post("http://127.0.0.1:{}/shutdown".format(settings.web.port), timeout=5)
            except Exception:
                pass
            web_thread.join(timeout=10)

        logger.info("GateKeeper 系统已停止")
        log_security_event(
            user="system",
            action="system_stop",
            resource="gatekeeper",
            result="success",
            message="GateKeeper 系统停止"
        )

    def get_status(self) -> dict:
        """获取系统运行状态"""
        scheduler = self._components.get("scheduler")
        db_mgr = _lazy_import("core.database", ["db_manager"])[0]
        return {
            "running": self._running,
            "version": settings.version,
            "components": {
                name: "active" for name in self._components
            },
            "scheduler_running": scheduler.is_running if scheduler else False,
            "tasks": list(scheduler.list_tasks().keys()) if scheduler else [],
            "database": db_mgr.check_health() if db_mgr else {"status": "unavailable"},
        }

    def reload_config(self):
        """重新加载配置"""
        logger.info("重新加载系统配置...")
        scheduler = self._components.get("scheduler")
        if scheduler:
            scheduler.stop()
            scheduler.register_default_tasks()
            scheduler.start()
        else:
            logger.warning("任务调度器不可用，跳过配置重载")
        logger.info("配置重新加载完成")


def main():
    """主入口函数"""
    import argparse

    parser = argparse.ArgumentParser(
        description="GateKeeper - AI安全网络防御系统"
    )
    parser.add_argument(
        "--no-web", action="store_true",
        help="不启动Web管理面板"
    )
    parser.add_argument(
        "--capture", action="store_true",
        help="启动数据包捕获"
    )
    parser.add_argument(
        "--init-only", action="store_true",
        help="仅初始化数据库，不启动服务"
    )
    parser.add_argument(
        "--version", action="store_true",
        help="显示版本信息"
    )

    args = parser.parse_args()

    if args.version:
        print("GateKeeper v{}".format(settings.version))
        return

    logger.info("GateKeeper v{} 启动中...".format(settings.version))

    app = GateKeeper()

    if not app.initialize():
        logger.error("系统初始化失败，请检查配置和日志")
        sys.exit(1)

    if args.init_only:
        logger.info("仅初始化模式，系统将退出")
        return

    app.start(
        enable_web=not args.no_web,
        enable_capture=args.capture,
    )

    # 等待Web服务启动
    if not args.no_web:
        time.sleep(3)
        if not app._web_started:
            logger.error("Web服务未能成功启动，请检查上方错误日志")

    # 主线程等待
    try:
        while app._running:
            time.sleep(1)
    except KeyboardInterrupt:
        app.stop()


if __name__ == "__main__":
    main()
