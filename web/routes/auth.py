"""
GateKeeper - 认证路由
用户登录、登出、会话管理和双因素认证(2FA)
"""

from flask import Blueprint, render_template, jsonify, request, redirect, url_for, current_app
from flask_login import (
    login_user, logout_user, login_required, current_user
)
# 重新导出 login_required，供其他路由模块使用
# (flask_login 的 login_required 是标准装饰器，安全可复用)
__all__ = ["auth_bp", "login_required", "admin_required", "super_admin_required"]
from functools import wraps
from datetime import datetime, timedelta

from config.logging_config import get_logger, log_security_event
from config.settings import settings
from core.database import db_manager
from core.models import User, UserRole
from utils.crypto import verify_password
from web.app import _safe_error_message

logger = get_logger("auth")


def super_admin_required(f):
    """超级管理员权限装饰器 - 仅允许 super_admin 角色访问"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != UserRole.SUPER_ADMIN:
            return jsonify({"status": "error", "message": "需要超级管理员权限"}), 403
        return f(*args, **kwargs)
    return decorated_function


def admin_required(f):
    """管理员权限装饰器 - 允许 admin 和 super_admin 角色访问"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role not in (UserRole.ADMIN, UserRole.SUPER_ADMIN):
            return jsonify({"status": "error", "message": "需要管理员权限"}), 403
        return f(*args, **kwargs)
    return decorated_function


auth_bp = Blueprint("auth", __name__)


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    """
    用户登录
    ---
    tags: [认证]
    parameters:
      - name: body
        in: body
        required: true
        schema:
          type: object
          properties:
            username:
              type: string
              example: admin
            password:
              type: string
              example: "your_password"
    responses:
      200:
        description: 登录成功
        schema:
          type: object
          properties:
            status:
              type: string
              example: ok
            data:
              type: object
              properties:
                username:
                  type: string
                role:
                  type: string
      401:
        description: 认证失败
      429:
        description: 请求过于频繁
      403:
        description: 账户被锁定或禁用
    """
    if request.method == "GET":
        if current_user.is_authenticated:
            return redirect(url_for("dashboard.index"))
        return render_template("login.html", title="登录")

    # POST: 处理登录请求
    try:
        data = request.get_json(force=True, silent=True) or {}
    except Exception:
        data = {}
    username = str(data.get("username", "") or "").strip()
    password = str(data.get("password", "") or "")

    if not username or not password:
        return jsonify({"status": "error", "message": "用户名和密码不能为空"}), 400

    try:
        with db_manager.get_session() as session:
            user = session.query(User).filter_by(username=username).first()

            if not user:
                log_security_event(
                    user=username,
                    action="login",
                    resource="auth",
                    result="failure",
                    message="用户不存在"
                )
                return jsonify({"status": "error", "message": "用户名或密码错误"}), 401

            # 检查账户锁定
            if user.locked_until and user.locked_until > datetime.now():
                remaining = (user.locked_until - datetime.now()).seconds
                return jsonify({
                    "status": "error",
                    "message": "账户已锁定，请{}秒后重试".format(remaining),
                }), 403

            # 检查账户状态
            if not user.is_active:
                return jsonify({"status": "error", "message": "账户已被禁用"}), 403

            # 验证密码
            if not verify_password(password, user.password_hash):
                user.login_attempts += 1

                # 检查是否达到最大尝试次数
                if user.login_attempts >= settings.web.max_login_attempts:
                    user.locked_until = datetime.now() + timedelta(
                        minutes=settings.web.login_lockout_time
                    )
                    log_security_event(
                        user=username,
                        action="login",
                        resource="auth",
                        result="locked",
                        message="账户锁定: 尝试次数={}".format(user.login_attempts)
                    )

                return jsonify({"status": "error", "message": "用户名或密码错误"}), 401

            # 登录成功 - 重置锁定状态
            user.login_attempts = 0
            user.locked_until = None
            user.last_login = datetime.now()
            session.expunge(user)

            # 检查用户是否启用了2FA
            try:
                from security.two_factor import get_two_factor_auth
                tfa = get_two_factor_auth()
                if tfa.is_2fa_enabled(user.id):
                    temp_token = tfa.create_temp_token(user.id, user.username)
                    log_security_event(
                        user=user.username,
                        action="login_2fa_required",
                        resource="auth",
                        result="pending",
                        message="用户{}需要2FA验证".format(user.username)
                    )
                    return jsonify({
                        "status": "2fa_required",
                        "message": "请输入双因素认证验证码",
                        "data": {
                            "temp_token": temp_token,
                        },
                    })
            except Exception as e:
                logger.warning("检查2FA状态失败，跳过2FA验证: {}".format(e))

            # 无需2FA，检查是否需要强制修改密码
            if user.must_change_password:
                login_user(user, remember=False)
                return jsonify({
                    "status": "must_change_password",
                    "message": "首次登录需要修改密码",
                    "redirect": url_for("settings.api_change_password")
                })

            login_user(user, remember=True)

            log_security_event(
                user=user.username,
                action="login",
                resource="auth",
                result="success",
                message="用户登录成功: {}".format(user.username)
            )

            try:
                from core.audit import log_web_action
                log_web_action(
                    action="login", module="auth",
                    detail="用户登录成功: {}".format(user.username)
                )
            except Exception:
                pass

            return jsonify({
                "status": "ok",
                "data": {
                    "username": user.username,
                    "role": user.role.value,
                },
            })

    except Exception as e:
        logger.error("登录处理失败: {} - {}".format(type(e).__name__, e), exc_info=True)
        return jsonify({"status": "error", "message": "登录失败"}), 500


@auth_bp.route("/logout", methods=["POST"])
@login_required
def logout():
    """
    用户登出
    ---
    tags: [认证]
    security:
      - cookieAuth: []
    responses:
      200:
        description: 登出成功
        schema:
          type: object
          properties:
            status:
              type: string
              example: ok
      401:
        description: 未认证
    """
    try:
        username = current_user.username
        logout_user()

        log_security_event(
            user=username,
            action="logout",
            resource="auth",
            result="success",
            message="用户登出: {}".format(username)
        )

        # 记录操作审计日志
        try:
            from core.audit import log_web_action
            log_web_action(
                action="logout", module="auth",
                detail="用户登出: {}".format(username)
            )
        except Exception:
            pass

        return jsonify({"status": "ok"})
    except Exception as e:
        logger.error("登出处理失败: {}".format(e))
        return jsonify({"status": "error", "message": "登出失败"}), 500


@auth_bp.route("/api/me")
@login_required
def api_me():
    """
    获取当前用户信息
    ---
    tags: [认证]
    security:
      - cookieAuth: []
    responses:
      200:
        description: 当前用户信息
        schema:
          type: object
          properties:
            status:
              type: string
              example: ok
            data:
              type: object
              properties:
                id:
                  type: integer
                username:
                  type: string
                email:
                  type: string
                role:
                  type: string
                last_login:
                  type: string
                  nullable: true
      401:
        description: 未认证
    """
    try:
        return jsonify({
            "status": "ok",
            "data": {
                "id": current_user.id,
                "username": current_user.username,
                "email": current_user.email,
                "role": current_user.role.value,
                "last_login": str(current_user.last_login) if current_user.last_login else None,
            },
        })
    except Exception as e:
        logger.error("获取用户信息失败: {}".format(e))
        return jsonify({"status": "error", "message": "获取用户信息失败"}), 500


# ============================================================
# 双因素认证(2FA)路由
# ============================================================

@auth_bp.route("/2fa/verify", methods=["POST"])
def verify_2fa():
    """
    验证2FA验证码
    请求体: {"temp_token": "...", "code": "123456"}
    """
    data = request.json if request.is_json else {}
    temp_token = data.get("temp_token", "")
    code = data.get("code", "")

    if not temp_token or not code:
        return jsonify({"status": "error", "message": "缺少必要参数"}), 400

    try:
        from security.two_factor import get_two_factor_auth
        tfa = get_two_factor_auth()

        # 验证临时令牌
        token_data = tfa.consume_temp_token(temp_token)
        if not token_data:
            log_security_event(
                user="unknown",
                action="2fa_verify",
                resource="auth",
                result="failure",
                message="2FA临时令牌无效或已过期"
            )
            return jsonify({"status": "error", "message": "验证令牌无效或已过期，请重新登录"}), 401

        user_id = token_data["user_id"]
        username = token_data["username"]

        # 验证2FA码
        if not tfa.validate_login(user_id, code):
            return jsonify({"status": "error", "message": "验证码错误，请重试"}), 401

        # 2FA验证成功，执行登录
        with db_manager.get_session() as session:
            user = session.query(User).filter_by(id=user_id).first()
            if not user:
                return jsonify({"status": "error", "message": "用户不存在"}), 404
            if not user.is_active:
                return jsonify({"status": "error", "message": "用户已被禁用"}), 403
            # 检查是否需要强制修改密码
            must_change = user.must_change_password
            # 防止 DetachedInstanceError：在session关闭前分离对象
            session.expunge(user)

        # 检查是否需要强制修改密码（在 login_user 之前检查）
        if must_change:
            login_user(user, remember=False)
            return jsonify({
                "status": "must_change_password",
                "message": "首次登录需要修改密码",
                "redirect": url_for("settings.api_change_password")
            })

        login_user(user, remember=True)

        log_security_event(
            user=username,
            action="login",
            resource="auth",
            result="success",
            message="用户2FA验证通过并登录成功: {}".format(username)
        )

        try:
            from core.audit import log_web_action
            log_web_action(
                action="login_2fa", module="auth",
                detail="用户2FA验证通过并登录: {}".format(username)
            )
        except Exception:
            pass

        return jsonify({
            "status": "ok",
            "data": {
                "username": user.username,
                "role": user.role.value,
            },
        })

    except Exception as e:
        logger.error("2FA验证失败: {}".format(e))
        return jsonify({"status": "error", "message": "验证失败"}), 500


@auth_bp.route("/2fa/setup", methods=["POST"])
@login_required
def setup_2fa():
    """
    开始设置2FA
    返回secret和QR URI供用户扫描
    """
    try:
        from security.two_factor import get_two_factor_auth
        tfa = get_two_factor_auth()

        # 生成新密钥
        secret = tfa.generate_secret()
        uri = tfa.get_totp_uri(current_user.username, secret)
        backup_codes = tfa.generate_backup_codes(10)

        log_security_event(
            user=current_user.username,
            action="2fa_setup_start",
            resource="auth",
            result="pending",
            message="用户{}开始设置2FA".format(current_user.username)
        )

        return jsonify({
            "status": "ok",
            "data": {
                "secret": secret,
                "qr_uri": uri,
                "backup_codes": backup_codes,
            },
        })

    except Exception as e:
        logger.error("2FA设置失败: {}".format(e))
        return jsonify({"status": "error", "message": "设置失败"}), 500


@auth_bp.route("/2fa/enable", methods=["POST"])
@login_required
def enable_2fa():
    """
    确认启用2FA
    请求体: {"secret": "...", "code": "123456", "backup_codes": ["..."]}
    """
    data = request.json if request.is_json else {}
    secret = data.get("secret", "")
    code = data.get("code", "")
    backup_codes = data.get("backup_codes", [])

    if not secret or not code:
        return jsonify({"status": "error", "message": "缺少必要参数"}), 400

    try:
        from security.two_factor import get_two_factor_auth
        tfa = get_two_factor_auth()

        # 验证用户输入的验证码是否正确
        if not tfa.verify_code(secret, code):
            return jsonify({"status": "error", "message": "验证码错误，请确认时间同步后重试"}), 400

        # 启用2FA
        if not backup_codes:
            backup_codes = tfa.generate_backup_codes(10)

        success = tfa.enable_2fa(current_user.id, secret, backup_codes)
        if not success:
            return jsonify({"status": "error", "message": "启用2FA失败"}), 500

        try:
            from core.audit import log_web_action
            log_web_action(
                action="2fa_enable", module="auth",
                detail="用户{}启用了双因素认证".format(current_user.username)
            )
        except Exception:
            pass

        return jsonify({
            "status": "ok",
            "message": "双因素认证已启用",
            "data": {
                "backup_codes": backup_codes,
            },
        })

    except Exception as e:
        logger.error("启用2FA失败: {}".format(e))
        return jsonify({"status": "error", "message": "启用失败"}), 500


@auth_bp.route("/2fa/disable", methods=["POST"])
@login_required
def disable_2fa():
    """
    禁用2FA
    请求体: {"password": "当前密码"}
    """
    data = request.json if request.is_json else {}
    password = data.get("password", "")

    if not password:
        return jsonify({"status": "error", "message": "请输入当前密码以确认操作"}), 400

    try:
        # 验证当前密码
        with db_manager.get_session() as session:
            user = session.query(User).filter_by(id=current_user.id).first()
            if not user or not verify_password(password, user.password_hash):
                return jsonify({"status": "error", "message": "密码错误"}), 401

        from security.two_factor import get_two_factor_auth
        tfa = get_two_factor_auth()

        if not tfa.is_2fa_enabled(current_user.id):
            return jsonify({"status": "error", "message": "双因素认证未启用"}), 400

        success = tfa.disable_2fa(current_user.id)
        if not success:
            return jsonify({"status": "error", "message": "禁用2FA失败"}), 500

        try:
            from core.audit import log_web_action
            log_web_action(
                action="2fa_disable", module="auth",
                detail="用户{}禁用了双因素认证".format(current_user.username)
            )
        except Exception:
            pass

        return jsonify({
            "status": "ok",
            "message": "双因素认证已禁用",
        })

    except Exception as e:
        logger.error("禁用2FA失败: {}".format(e))
        return jsonify({"status": "error", "message": "禁用失败"}), 500


@auth_bp.route("/2fa/status", methods=["GET"])
@login_required
def status_2fa():
    """获取当前用户2FA状态"""
    try:
        from security.two_factor import get_two_factor_auth
        tfa = get_two_factor_auth()

        config = tfa.get_user_2fa(current_user.id)
        if not config:
            return jsonify({
                "status": "ok",
                "data": {
                    "enabled": False,
                },
            })

        return jsonify({
            "status": "ok",
            "data": {
                "enabled": config.enabled,
                "created_at": config.created_at.isoformat() if config.created_at else None,
                "last_used": config.last_used.isoformat() if config.last_used else None,
                "backup_codes_count": len(config.backup_codes),
            },
        })

    except Exception as e:
        logger.error("获取2FA状态失败: {}".format(e))
        return jsonify({"status": "error", "message": "获取状态失败"}), 500


@auth_bp.route("/2fa/backup-codes", methods=["GET"])
@login_required
def get_backup_codes():
    """重新生成备用恢复码"""
    try:
        from security.two_factor import get_two_factor_auth
        tfa = get_two_factor_auth()

        if not tfa.is_2fa_enabled(current_user.id):
            return jsonify({"status": "error", "message": "双因素认证未启用"}), 400

        new_codes = tfa.regenerate_backup_codes(current_user.id)
        if not new_codes:
            return jsonify({"status": "error", "message": "重新生成备用码失败"}), 500

        try:
            from core.audit import log_web_action
            log_web_action(
                action="2fa_backup_regenerate", module="auth",
                detail="用户{}重新生成了备用恢复码".format(current_user.username)
            )
        except Exception:
            pass

        return jsonify({
            "status": "ok",
            "data": {
                "backup_codes": new_codes,
            },
        })

    except Exception as e:
        logger.error("重新生成备用码失败: {}".format(e))
        return jsonify({"status": "error", "message": "操作失败"}), 500
