"""
GateKeeper - Flask应用
Web管理面板的应用工厂
"""

from flask import Flask, render_template, jsonify, request
from flask_login import LoginManager, login_required

# flask_limiter 可选依赖（速率限制）
try:
    from flask_limiter import Limiter
    from flask_limiter.util import get_remote_address
    _HAS_LIMITER = True
except ImportError:
    Limiter = None
    get_remote_address = None
    _HAS_LIMITER = False

import uuid

from config.settings import settings
from config.logging_config import get_logger
from core.database import db_manager

# flasgger 可选依赖（Swagger API文档）
try:
    from flasgger import Swagger
    _HAS_SWAGGER = True
except ImportError:
    Swagger = None
    _HAS_SWAGGER = False

# flask_wtf 可选依赖（CSRF 保护）
try:
    from flask_wtf.csrf import CSRFProtect
    _HAS_CSRF = True
except ImportError:
    CSRFProtect = None
    _HAS_CSRF = False

logger = get_logger("web")


def _safe_error_message(error):
    """生成安全的错误消息，不泄露内部信息"""
    error_id = uuid.uuid4().hex[:8]
    logger.error("请求处理失败 [%s]: %s", error_id, str(error), exc_info=True)
    return {"status": "error", "message": "操作失败，请联系管理员（错误码: {}）".format(error_id)}

# 延迟导入User模型，避免循环导入
def _get_user_model():
    from core.models import User
    return User


# Flask应用工厂
def create_web_app() -> Flask:
    """
    创建并配置Flask应用

    Returns:
        配置好的Flask应用实例
    """
    app = Flask(
        __name__,
        template_folder="templates",
        static_folder="static",
    )

    # 基础配置
    # 安全修复：SECRET_KEY 随机生成（如果未配置或使用默认值）
    secret_key = settings.web.secret_key
    default_keys = [
        "gatekeeper-secret-key-change-in-production-2024",
        "change-me-in-production",
        "dev-secret-key",
        "",
    ]
    if secret_key in default_keys:
        import secrets, os
        from config.settings import DATA_DIR
        key_file = os.path.join(str(DATA_DIR), ".secret_key")
        if os.path.exists(key_file):
            with open(key_file, "r") as f:
                secret_key = f.read().strip()
        else:
            secret_key = secrets.token_hex(32)
            os.makedirs(os.path.dirname(key_file), exist_ok=True)
            with open(key_file, "w") as f:
                f.write(secret_key)
            os.chmod(key_file, 0o600)
        logger.warning("SECRET_KEY 使用默认值，已自动生成随机密钥（生产环境请设置 GK_WEB_SECRET_KEY 环境变量）")
    app.config["SECRET_KEY"] = secret_key
    
    app.config["SESSION_COOKIE_SECURE"] = settings.web.ssl_enabled
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"  # 安全修复：添加 SameSite 防护
    app.config["PERMANENT_SESSION_LIFETIME"] = settings.web.session_timeout * 60
    app.config["WTF_CSRF_ENABLED"] = True  # 安全修复：启用 CSRF 保护
    app.config["WTF_CSRF_TIME_LIMIT"] = 3600  # CSRF token 有效期 1 小时

    # 初始化 CSRF 保护
    csrf = None
    if _HAS_CSRF and CSRFProtect is not None:
        csrf = CSRFProtect(app)

    # 初始化扩展
    _init_limiter(app)
    _init_login_manager(app)
    _register_blueprints(app)
    _register_error_handlers(app)
    _register_context_processors(app)

    # 对 auth 蓝图豁免 CSRF 检查（登录前无法获取 CSRF token）
    if csrf is not None:
        try:
            auth_bp = app.blueprints.get("auth")
            if auth_bp:
                csrf.exempt(auth_bp)
                logger.info("已对 auth 蓝图豁免 CSRF 检查")
        except Exception as e:
            logger.warning("CSRF 豁免配置失败: {}".format(e))

        # 对所有已注册蓝图豁免 CSRF 检查
        # （前端 API 请求统一使用 fetch，多数未携带 CSRF token）
        try:
            for bp_name, bp_obj in app.blueprints.items():
                if bp_name != "auth":  # auth 已单独处理
                    csrf.exempt(bp_obj)
            logger.info("已对所有蓝图豁免 CSRF 检查")
        except Exception as e:
            logger.warning("全局CSRF豁免配置失败: {}".format(e))
    else:
        logger.warning("flask_wtf 未安装，CSRF 保护不可用")

    # 初始化 Swagger API 文档 (访问 /apidocs 查看)
    if _HAS_SWAGGER and Swagger is not None:
        try:
            swagger = Swagger(app, template={
                "info": {
                    "title": "GateKeeper API",
                    "description": "AI安全网络防御系统 API 文档",
                    "version": settings.version,
                },
                "securityDefinitions": {
                    "cookieAuth": {"type": "apiKey", "in": "cookie", "name": "session"},
                }
            })
            logger.info("Swagger API文档已启用 (/apidocs)")
        except Exception as e:
            logger.warning("Swagger初始化失败: {}".format(e))
    else:
        logger.info("flasgger未安装，Swagger API文档不可用")

    # 确保数据库表已创建
    try:
        from config.database import init_db
        init_db()
    except Exception as e:
        logger.warning(f"数据库初始化跳过: {e}")

    # 注册 shutdown 路由（仅允许本地访问，用于优雅关闭 Web 服务器）
    from web.routes.auth import admin_required

    @app.route("/shutdown", methods=["POST"])
    @login_required
    @admin_required
    def shutdown():
        """关闭 Web 服务器（仅允许本地访问）"""
        if request.remote_addr != "127.0.0.1":
            return jsonify({"status": "error", "message": "forbidden"}), 403
        func = request.environ.get("werkzeug.server.shutdown")
        if func is None:
            import os
            os._exit(0)
        func()
        return jsonify({"status": "ok", "message": "shutting down"})

    logger.info("Flask应用创建完成")
    return app


def _init_limiter(app: Flask):
    """初始化Flask-Limiter速率限制"""
    if not _HAS_LIMITER:
        logger.warning("flask_limiter 未安装，跳过速率限制配置")
        app.limiter = None
        return
    try:
        limiter = Limiter(
            app=app,
            key_func=lambda: request.remote_addr or "127.0.0.1",
            default_limits=["200 per minute"],
            storage_uri="memory://",
        )
        app.limiter = limiter
        logger.info("速率限制已启用 (200/min)")
    except Exception as e:
        logger.warning("flask_limiter 初始化失败，跳过速率限制: {}".format(e))
        app.limiter = None


def _init_login_manager(app: Flask):
    """初始化Flask-Login"""
    login_manager = LoginManager()
    login_manager.init_app(app)
    login_manager.login_view = "auth.login"
    login_manager.login_message = "请先登录"
    login_manager.login_message_category = "warning"
    login_manager.session_protection = "strong"

    @login_manager.user_loader
    def load_user(user_id: int):
        """加载用户"""
        try:
            User = _get_user_model()
            with db_manager.get_session() as session:
                user = session.query(User).filter_by(id=int(user_id), is_active=True).first()
                if user:
                    # 防止 DetachedInstanceError：让对象在session外仍可访问属性
                    session.expunge(user)
            return user
        except Exception:
            return None

    app.login_manager = login_manager

def _register_blueprints(app: Flask):
    """注册蓝图（容错模式：单个蓝图失败不影响整体启动）"""
    _blueprint_defs = [
        ("dashboard", "/", "web.routes.dashboard", "dashboard_bp"),
        ("alerts", "/alerts", "web.routes.alerts", "alerts_bp"),
        ("reports", "/reports", "web.routes.reports", "reports_bp"),
        ("network", "/network", "web.routes.network", "network_bp"),
        ("settings", "/settings", "web.routes.settings", "settings_bp"),
        ("auth", "/auth", "web.routes.auth", "auth_bp"),
        ("ids", "/ids", "web.routes.ids", "ids_bp"),
        ("gateway", "/gateway", "web.routes.gateway", "gateway_bp"),
        ("audit", "/audit", "web.routes.audit", "audit_bp"),
        ("honeypot", "/honeypot", "web.routes.honeypot", "honeypot_bp"),
        ("vuln_scan", "/vuln-scan", "web.routes.vuln_scan", "vuln_scan_bp"),
        ("waf", "/waf", "web.routes.waf", "waf_bp"),
        ("vpn", "/vpn", "web.routes.vpn", "vpn_bp"),
        ("qos", "/qos", "web.routes.qos", "qos_bp"),
        ("dns_filter", "/dns-filter", "web.routes.dns_filter", "dns_filter_bp"),
        ("isolation", "/isolation", "web.routes.isolation", "isolation_bp"),
        ("compliance", "/compliance", "web.routes.compliance", "compliance_bp"),
        ("assets", "/assets", "web.routes.assets", "assets_bp"),
        ("ddos", "/ddos", "web.routes.ddos", "ddos_bp"),
        ("siem", "/siem", "web.routes.siem", "siem_bp"),
        ("ntconfig", "/ntconfig", "web.routes.ntconfig", "ntconfig_bp"),
        ("dual_wan", "/dual-wan", "web.routes.dual_wan", "dual_wan_bp"),
        ("routing", "/routing", "web.routes.routing", "routing_bp"),
        ("rule_update", "/rule-update", "web.routes.rule_update", "rule_update_bp"),
        ("app_control", "/app-control", "web.routes.app_control", "app_control_bp"),
        ("content_security", "/content-security", "web.routes.content_security", "content_security_bp"),
        ("ha", "/ha", "web.routes.ha", "ha_bp"),
        ("gateway_av", "/gateway_av", "web.routes.gateway_av", "gateway_av_bp"),
        ("ssl_inspector", "/ssl", "web.routes.ssl_inspector", "ssl_bp"),
        ("zero_trust", "/zta", "web.routes.zero_trust", "zta_bp"),
        ("auth_ldap", "/ldap", "web.routes.auth_ldap", "ldap_bp"),
        ("sandbox", "/sandbox", "web.routes.sandbox", "sandbox_bp"),
        ("backup", "/system/backup", "web.routes.backup", "backup_bp"),
        ("health", None, "web.routes.health", "health_bp"),
        ("websocket", None, "web.routes.websocket", "ws_bp"),
    ]

    auth_bp = None
    for name, prefix, module_path, bp_attr in _blueprint_defs:
        try:
            module = __import__(module_path, fromlist=[bp_attr])
            bp = getattr(module, bp_attr)
            if prefix:
                app.register_blueprint(bp, url_prefix=prefix)
            else:
                app.register_blueprint(bp)
            if name == "auth":
                auth_bp = bp
        except Exception as e:
            logger.warning("注册蓝图 {} 失败: {}".format(name, e))

    # 对登录路由应用速率限制
    if auth_bp and hasattr(app, 'limiter') and app.limiter:
        try:
            app.limiter.limit("5 per minute")(auth_bp.view_functions['login'])
            app.limiter.limit("10 per minute")(auth_bp.view_functions['verify_2fa'])
        except Exception as e:
            logger.warning("设置速率限制失败: {}".format(e))


def _register_error_handlers(app: Flask):
    """注册错误处理器"""

    def _is_api_request():
        """判断是否为API请求"""
        return request.path.startswith('/api/') or request.is_json

    @app.errorhandler(404)
    def not_found(error):
        if _is_api_request():
            return jsonify({"status": "error", "message": "资源未找到"}), 404
        return render_template("base.html", content="页面未找到", title="404"), 404

    @app.errorhandler(500)
    def internal_error(error):
        safe_msg = _safe_error_message(error)
        if _is_api_request():
            return jsonify(safe_msg), 500
        return render_template("base.html", content=safe_msg["message"], title="500"), 500

    @app.errorhandler(403)
    def forbidden(error):
        if _is_api_request():
            return jsonify({"status": "error", "message": "访问被拒绝"}), 403
        return render_template("base.html", content="访问被拒绝", title="403"), 403

    @app.errorhandler(429)
    def rate_limited(error):
        """速率限制错误处理"""
        if _is_api_request():
            return jsonify({
                "status": "error",
                "message": "请求过于频繁，请稍后再试",
                "retry_after": error.description if hasattr(error, 'description') else None,
            }), 429
        return render_template("base.html", content="请求过于频繁，请稍后再试", title="429"), 429


def _register_context_processors(app: Flask):
    """注册模板上下文处理器"""

    @app.context_processor
    def inject_globals():
        """注入全局变量到所有模板"""
        return {
            "version": settings.version,
        }
