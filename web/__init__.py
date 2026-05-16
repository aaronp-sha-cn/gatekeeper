"""
GateKeeper - Web模块
Flask Web管理面板
"""

__all__ = ["create_web_app"]


def __getattr__(name):
    """延迟导入，避免模块级导入失败导致整个web模块不可用"""
    if name == "create_web_app":
        from web.app import create_web_app
        return create_web_app
    raise AttributeError("module '{}' has no attribute '{}'".format(__name__, name))
