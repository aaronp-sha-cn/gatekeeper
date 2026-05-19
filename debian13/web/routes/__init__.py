"""Web路由模块"""
from web.routes.dashboard import dashboard_bp
from web.routes.alerts import alerts_bp
from web.routes.reports import reports_bp
from web.routes.network import network_bp
from web.routes.settings import settings_bp
from web.routes.auth import auth_bp
from web.routes.isolation import isolation_bp
from web.routes.dual_wan import dual_wan_bp

__all__ = [
    "dashboard_bp", "alerts_bp", "reports_bp",
    "network_bp", "settings_bp", "auth_bp",
    "isolation_bp", "dual_wan_bp",
]
