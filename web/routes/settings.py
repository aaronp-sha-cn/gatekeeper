"""
GateKeeper - 系统设置路由
"""

import json
import subprocess
import time
import os

import requests as http_requests
from flask import Blueprint, jsonify, render_template, request
from flask_login import current_user, login_required
from datetime import datetime

from config.settings import settings
from config.logging_config import get_logger, log_security_event
from core.audit import log_web_action
from core.models import User, UserRole, SystemConfig
from web.routes.auth import super_admin_required, admin_required
from web.app import _safe_error_message
from core.database import db_manager
from utils.crypto import verify_password, hash_password, encrypt_data, decrypt_data

logger = get_logger("web.settings")

settings_bp = Blueprint("settings", __name__)


@settings_bp.route("/")
@login_required
def index():
    """设置页面"""
    return render_template("settings.html", title="系统设置")


@settings_bp.route("/api/config", methods=["GET"])
@login_required
def api_get_config():
    """获取系统配置"""
    try:
        with db_manager.get_session() as session:
            configs = session.query(SystemConfig).all()
            config_dict = {}
            for c in configs:
                if c.category not in config_dict:
                    config_dict[c.category] = {}
                config_dict[c.category][c.key] = {
                    "value": c.value,
                    "type": c.value_type,
                    "description": c.description,
                    "readonly": c.is_readonly,
                }
            return jsonify({"status": "ok", "data": config_dict})
    except Exception as e:
        return jsonify(_safe_error_message(e)), 500


@settings_bp.route("/api/config", methods=["POST"])
@admin_required
def api_update_config():
    """更新系统配置"""
    data = request.json if request.is_json else {}
    category = data.get("category", "")
    key = data.get("key", "")
    value = str(data.get("value", ""))

    if not category or not key:
        return jsonify({"status": "error", "message": "缺少必要参数"}), 400

    try:
        with db_manager.get_session() as session:
            config = (
                session.query(SystemConfig)
                .filter_by(category=category, key=key)
                .first()
            )
            if config:
                if config.is_readonly:
                    return jsonify({"status": "error", "message": "此配置为只读"}), 403
                config.value = value
                config.updated_at = datetime.now()
            else:
                config = SystemConfig(
                    category=category,
                    key=key,
                    value=value,
                    value_type=data.get("type", "string"),
                    description=data.get("description", ""),
                )
                session.add(config)

            log_security_event(
                user=current_user.username,
                action="config_update",
                resource="{}.{}".format(category, key),
                result="success",
                message="更新配置: {}.{} = {}".format(category, key, value)
            )

            return jsonify({"status": "ok"})
    except Exception as e:
        return jsonify(_safe_error_message(e)), 500


@settings_bp.route("/api/users", methods=["GET"])
@admin_required
def api_get_users():
    """获取用户列表"""
    try:
        with db_manager.get_session() as session:
            users = session.query(User).all()
            return jsonify({
                "status": "ok",
                "data": [
                    {
                        "id": u.id,
                        "username": u.username,
                        "email": u.email,
                        "role": u.role.value,
                        "is_active": u.is_active,
                        "last_login": str(u.last_login) if u.last_login else None,
                        "created_at": str(u.created_at),
                    }
                    for u in users
                ],
            })
    except Exception as e:
        return jsonify(_safe_error_message(e)), 500


@settings_bp.route("/api/users", methods=["POST"])
@admin_required
def api_create_user():
    """创建用户"""
    import re
    data = request.json if request.is_json else {}
    username = data.get("username", "")
    password = data.get("password", "")
    email = data.get("email", "")
    role = data.get("role", "VIEWER")

    if not username or not password:
        return jsonify({"status": "error", "message": "用户名和密码不能为空"}), 400

    # 安全修复：密码复杂度验证
    if len(password) < 8:
        return jsonify({"status": "error", "message": "密码长度至少 8 位"}), 400
    if not re.search(r'[A-Z]', password):
        return jsonify({"status": "error", "message": "密码必须包含大写字母"}), 400
    if not re.search(r'[a-z]', password):
        return jsonify({"status": "error", "message": "密码必须包含小写字母"}), 400
    if not re.search(r'[0-9]', password):
        return jsonify({"status": "error", "message": "密码必须包含数字"}), 400
    if not re.search(r'[!@#$%^&*()_+\-=\[\]{};:\'",.<>/?\\|`~]', password):
        return jsonify({"status": "error", "message": "密码必须包含特殊字符"}), 400

    try:
        with db_manager.get_session() as session:
            existing = session.query(User).filter_by(username=username).first()
            if existing:
                return jsonify({"status": "error", "message": "用户名已存在"}), 400

            user = User(
                username=username,
                email=email,
                password_hash=hash_password(password),
                role=UserRole(role),
                is_active=True,
            )
            session.add(user)

            # 同步创建Linux系统用户
            _sync_system_user(username, password=password, action="create")

            log_security_event(
                user=current_user.username,
                action="user_create",
                resource=username,
                result="success",
            )

            return jsonify({"status": "ok", "user_id": user.id})
    except Exception as e:
        return jsonify(_safe_error_message(e)), 500


@settings_bp.route("/api/users/<int:user_id>", methods=["DELETE"])
@admin_required
def api_delete_user(user_id):
    """删除用户"""
    if current_user.id == user_id:
        return jsonify({"status": "error", "message": "不能删除自己"}), 400

    try:
        with db_manager.get_session() as session:
            user = session.query(User).filter_by(id=user_id).first()
            if not user:
                return jsonify({"status": "error", "message": "用户不存在"}), 404

            # 禁止非超管删除超管账户
            if user.role == UserRole.SUPER_ADMIN and current_user.role != UserRole.SUPER_ADMIN:
                return jsonify({"status": "error", "message": "无权删除超级管理员账户"}), 403

            username = user.username
            session.delete(user)

            # 同步删除Linux系统用户
            _sync_system_user(username, action="delete")

            log_security_event(
                user=current_user.username,
                action="user_delete",
                resource=username,
                result="success",
            )

            return jsonify({"status": "ok"})
    except Exception as e:
        logger.error("删除用户失败: {}".format(str(e)))
        return jsonify(_safe_error_message(e)), 500


@settings_bp.route("/api/users/<int:user_id>/toggle", methods=["POST"])
@admin_required
def api_toggle_user(user_id):
    """启用/禁用用户"""
    if current_user.id == user_id:
        return jsonify({"status": "error", "message": "不能禁用自己"}), 400

    try:
        with db_manager.get_session() as session:
            user = session.query(User).filter_by(id=user_id).first()
            if not user:
                return jsonify({"status": "error", "message": "用户不存在"}), 404

            # 禁止非超管操作超管账户
            if user.role == UserRole.SUPER_ADMIN and current_user.role != UserRole.SUPER_ADMIN:
                return jsonify({"status": "error", "message": "无权操作超级管理员账户"}), 403

            user.is_active = not user.is_active
            new_status = "启用" if user.is_active else "禁用"

            # 同步锁定/解锁Linux系统用户
            if user.is_active:
                _sync_system_user(user.username, action="unlock")
            else:
                _sync_system_user(user.username, action="lock")

            log_security_event(
                user=current_user.username,
                action="user_toggle",
                resource=user.username,
                result="success",
                message="{}用户: {}".format(new_status, user.username),
            )

            return jsonify({"status": "ok", "is_active": user.is_active})
    except Exception as e:
        logger.error("切换用户状态失败: {}".format(str(e)))
        return jsonify(_safe_error_message(e)), 500


@settings_bp.route("/api/change-password", methods=["POST"])
@login_required
def api_change_password():
    """修改密码"""
    import re
    data = request.json if request.is_json else {}
    old_password = data.get("old_password", "")
    new_password = data.get("new_password", "")

    if not old_password or not new_password:
        return jsonify({"status": "error", "message": "密码不能为空"}), 400

    # 安全修复：密码复杂度验证
    if len(new_password) < 8:
        return jsonify({"status": "error", "message": "密码长度至少 8 位"}), 400
    if not re.search(r'[A-Z]', new_password):
        return jsonify({"status": "error", "message": "密码必须包含大写字母"}), 400
    if not re.search(r'[a-z]', new_password):
        return jsonify({"status": "error", "message": "密码必须包含小写字母"}), 400
    if not re.search(r'[0-9]', new_password):
        return jsonify({"status": "error", "message": "密码必须包含数字"}), 400
    if not re.search(r'[!@#$%^&*()_+\-=\[\]{};:\'",.<>/?\\|`~]', new_password):
        return jsonify({"status": "error", "message": "密码必须包含特殊字符"}), 400

    try:
        with db_manager.get_session() as session:
            user = session.query(User).filter_by(id=current_user.id).first()
            if not user:
                return jsonify({"status": "error", "message": "用户不存在"}), 404

            if not verify_password(old_password, user.password_hash):
                return jsonify({"status": "error", "message": "原密码错误"}), 400

            user.password_hash = hash_password(new_password)
            user.must_change_password = False

            # 密码修改成功后，删除初始凭证环境文件，防止服务重启时重置密码
            try:
                import os
                from config.settings import DATA_DIR
                cred_env_file = os.path.join(str(DATA_DIR), ".initial_credentials.env")
                if os.path.exists(cred_env_file):
                    os.remove(cred_env_file)
                    logger.info("初始凭证环境文件已删除: {}".format(cred_env_file))
            except Exception as e:
                logger.warning("删除初始凭证环境文件失败: {}".format(e))

            log_security_event(
                user=current_user.username,
                action="password_change",
                resource=str(current_user.id),
                result="success",
            )

            return jsonify({"status": "ok"})
    except Exception as e:
        return jsonify(_safe_error_message(e)), 500


@settings_bp.route("/api/system/info")
@login_required
def api_system_info():
    """获取系统信息"""
    try:
        import platform
        import psutil

        info = {
            "gatekeeper_version": settings.version,
            "python_version": platform.python_version(),
            "os": platform.system(),
            "os_version": platform.release(),
            "hostname": platform.node(),
            "cpu_count": psutil.cpu_count(),
            "cpu_percent": psutil.cpu_percent(interval=1),
            "memory_total": psutil.virtual_memory().total,
            "memory_used": psutil.virtual_memory().used,
            "memory_percent": psutil.virtual_memory().percent,
            "disk_total": psutil.disk_usage("/").total,
            "disk_used": psutil.disk_usage("/").used,
            "disk_percent": psutil.disk_usage("/").percent,
        }

        return jsonify({"status": "ok", "data": info})
    except Exception as e:
        return jsonify({"status": "error", "message": "获取系统信息失败，请联系管理员"}), 500


@settings_bp.route("/api/system/hostname", methods=["POST"])
@admin_required
def api_set_hostname():
    """设置系统主机名"""
    data = request.json if request.is_json else {}
    new_hostname = data.get("hostname", "").strip()

    if not new_hostname:
        return jsonify({"status": "error", "message": "主机名不能为空"}), 400

    # 验证主机名格式
    import re
    if not re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$', new_hostname):
        return jsonify({"status": "error", "message": "主机名格式无效（仅允许字母、数字、连字符，2-63字符）"}), 400

    try:
        # 设置临时主机名
        subprocess.run(["hostname", new_hostname], check=True, capture_output=True, timeout=5)
        # 持久化到 /etc/hostname
        with open("/etc/hostname", "w") as f:
            f.write(new_hostname + "\n")
        # 更新 /etc/hosts 中的 127.0.1.1 条目
        try:
            with open("/etc/hosts", "r") as f:
                hosts_content = f.read()
            import re as _re
            hosts_content = _re.sub(
                r'^(127\.0\.1\.1\s+)\S+',
                r'\g<1>' + new_hostname,
                hosts_content,
                flags=_re.MULTILINE
            )
            with open("/etc/hosts", "w") as f:
                f.write(hosts_content)
        except Exception:
            pass

        log_web_action(
            action="set_hostname", module="settings",
            detail="修改主机名: {}".format(new_hostname)
        )
        return jsonify({"status": "ok", "message": "主机名已更新为: {}".format(new_hostname)})
    except subprocess.CalledProcessError as e:
        return jsonify({"status": "error", "message": "设置主机名失败，请联系管理员"}), 500
    except Exception as e:
        return jsonify(_safe_error_message(e)), 500


# ===== AI 提供商配置 API =====

AI_PROVIDER_CATEGORY = "ai_provider"


def _check_admin():
    """检查当前用户是否为管理员"""
    if current_user.role not in (UserRole.ADMIN, UserRole.SUPER_ADMIN):
        return False
    return True


def _sync_system_user(username, password=None, action="create", is_active=True):
    """
    同步Linux系统用户。
    action: create / delete / lock / unlock
    """
    import re
    # 用户名安全验证：仅允许字母、数字、下划线、连字符，长度1-32
    if not username or not re.match(r'^[a-zA-Z0-9_-]{1,32}$', username):
        logger.error("用户名格式无效: {}（仅允许字母、数字、下划线、连字符，长度1-32）".format(username))
        return False
    # 额外检查：不能以数字或连字符开头
    if username[0].isdigit() or username[0] == '-':
        logger.error("用户名不能以数字或连字符开头: {}".format(username))
        return False

    try:
        if action == "create":
            # 检查系统用户是否已存在
            r = subprocess.run(
                ["id", username], capture_output=True, text=True, timeout=5
            )
            if r.returncode == 0:
                logger.info("系统用户 {} 已存在，跳过创建".format(username))
                return True
            # 创建系统用户，设置bash和home目录
            r = subprocess.run(
                ["useradd", "-m", "-s", "/bin/bash", username],
                capture_output=True, text=True, timeout=10,
            )
            if r.returncode != 0:
                logger.error("创建系统用户失败: {}".format(r.stderr))
                return False
            # 设置密码
            if password:
                r = subprocess.run(
                    ["chpasswd"],
                    input="{}:{}".format(username, password),
                    capture_output=True, text=True, timeout=5,
                )
                if r.returncode != 0:
                    logger.error("设置系统用户密码失败: {}".format(r.stderr))
                    return False
            logger.info("系统用户 {} 创建成功".format(username))
            return True

        elif action == "delete":
            r = subprocess.run(
                ["id", username], capture_output=True, text=True, timeout=5
            )
            if r.returncode != 0:
                return True  # 用户不存在，无需删除
            r = subprocess.run(
                ["userdel", "-r", username],
                capture_output=True, text=True, timeout=10,
            )
            if r.returncode != 0:
                logger.error("删除系统用户失败: {}".format(r.stderr))
                return False
            logger.info("系统用户 {} 已删除".format(username))
            return True

        elif action == "lock":
            r = subprocess.run(
                ["passwd", "-l", username],
                capture_output=True, text=True, timeout=5,
            )
            if r.returncode != 0:
                logger.error("锁定系统用户失败: {}".format(r.stderr))
                return False
            logger.info("系统用户 {} 已锁定".format(username))
            return True

        elif action == "unlock":
            r = subprocess.run(
                ["passwd", "-u", username],
                capture_output=True, text=True, timeout=5,
            )
            if r.returncode != 0:
                logger.error("解锁系统用户失败: {}".format(r.stderr))
                return False
            logger.info("系统用户 {} 已解锁".format(username))
            return True

    except subprocess.TimeoutExpired:
        logger.error("系统用户操作超时: {}".format(username))
    except Exception as e:
        logger.error("系统用户操作异常: {}".format(str(e)))
    return False


@settings_bp.route("/api/ai/providers", methods=["GET"])
@admin_required
def api_get_ai_providers():
    """获取已配置的 AI 提供商列表"""
    try:
        with db_manager.get_session() as session:
            configs = (
                session.query(SystemConfig)
                .filter_by(category=AI_PROVIDER_CATEGORY)
                .all()
            )
            providers = []
            for c in configs:
                try:
                    provider_data = json.loads(c.value)
                    provider_data["provider_type"] = c.key
                    # 解密API密钥（如果已加密）
                    encrypted_key = provider_data.get("api_key", "")
                    if encrypted_key:
                        try:
                            decrypted_key = decrypt_data(encrypted_key)
                            # 只返回前8位和后4位，中间用***隐藏
                            if len(decrypted_key) > 12:
                                provider_data["api_key"] = decrypted_key[:8] + "***" + decrypted_key[-4:]
                            else:
                                provider_data["api_key"] = "***"
                        except Exception:
                            # 如果解密失败，可能是明文存储的旧数据
                            provider_data["api_key"] = "***"
                    providers.append(provider_data)
                except (json.JSONDecodeError, TypeError):
                    continue

            return jsonify({"status": "ok", "data": providers})
    except Exception as e:
        logger.error("获取 AI 提供商列表失败: {}".format(str(e)))
        return jsonify(_safe_error_message(e)), 500


@settings_bp.route("/api/ai/providers", methods=["POST"])
@admin_required
def api_save_ai_provider():
    """保存 AI 提供商配置"""
    data = request.json if request.is_json else {}
    provider_type = data.get("provider_type", "").strip()
    api_key = data.get("api_key", "").strip()
    api_base = data.get("api_base", "").strip()
    model = data.get("model", "").strip()
    temperature = data.get("temperature", 0.7)
    max_tokens = data.get("max_tokens", 4096)
    set_default = data.get("set_default", False)

    if not provider_type:
        return jsonify({"status": "error", "message": "缺少提供商类型"}), 400
    if not api_key:
        return jsonify({"status": "error", "message": "缺少 API Key"}), 400
    if not model:
        return jsonify({"status": "error", "message": "缺少模型名称"}), 400

    try:
        with db_manager.get_session() as session:
            # 如果设为默认，先清除其他默认标记
            if set_default:
                existing_configs = (
                    session.query(SystemConfig)
                    .filter_by(category=AI_PROVIDER_CATEGORY)
                    .all()
                )
                for ec in existing_configs:
                    try:
                        ec_data = json.loads(ec.value)
                        if ec_data.get("is_default", False):
                            ec_data["is_default"] = False
                            ec.value = json.dumps(ec_data, ensure_ascii=False)
                    except (json.JSONDecodeError, TypeError):
                        continue

            # 保存或更新配置（API密钥加密存储）
            encrypted_api_key = encrypt_data(api_key)
            provider_config = {
                "api_key": encrypted_api_key,
                "api_base": api_base,
                "model": model,
                "temperature": temperature,
                "max_tokens": max_tokens,
                "is_enabled": True,
                "is_default": set_default,
            }

            existing = (
                session.query(SystemConfig)
                .filter_by(category=AI_PROVIDER_CATEGORY, key=provider_type)
                .first()
            )

            if existing:
                # 保留原有的启用状态（除非是新设为默认）
                try:
                    old_data = json.loads(existing.value)
                    if not set_default:
                        provider_config["is_enabled"] = old_data.get("is_enabled", True)
                        provider_config["is_default"] = old_data.get("is_default", False)
                except (json.JSONDecodeError, TypeError):
                    pass
                existing.value = json.dumps(provider_config, ensure_ascii=False)
                existing.updated_at = datetime.now()
            else:
                config = SystemConfig(
                    category=AI_PROVIDER_CATEGORY,
                    key=provider_type,
                    value=json.dumps(provider_config, ensure_ascii=False),
                    value_type="json",
                    description="AI 提供商配置: {}".format(provider_type),
                )
                session.add(config)

            log_security_event(
                user=current_user.username,
                action="ai_provider_save",
                resource=provider_type,
                result="success",
                message="保存 AI 提供商配置: {}, 模型: {}".format(provider_type, model),
            )

            return jsonify({"status": "ok"})
    except Exception as e:
        logger.error("保存 AI 提供商配置失败: {}".format(str(e)))
        return jsonify(_safe_error_message(e)), 500


@settings_bp.route("/api/ai/providers/<provider_type>", methods=["DELETE"])
@admin_required
def api_delete_ai_provider(provider_type):
    """删除 AI 提供商配置"""
    try:
        with db_manager.get_session() as session:
            config = (
                session.query(SystemConfig)
                .filter_by(category=AI_PROVIDER_CATEGORY, key=provider_type)
                .first()
            )
            if not config:
                return jsonify({"status": "error", "message": "提供商配置不存在"}), 404

            session.delete(config)

            log_security_event(
                user=current_user.username,
                action="ai_provider_delete",
                resource=provider_type,
                result="success",
                message="删除 AI 提供商配置: {}".format(provider_type),
            )

            return jsonify({"status": "ok"})
    except Exception as e:
        logger.error("删除 AI 提供商配置失败: {}".format(str(e)))
        return jsonify(_safe_error_message(e)), 500


@settings_bp.route("/api/ai/providers/<provider_type>/default", methods=["POST"])
@admin_required
def api_set_default_ai_provider(provider_type):
    """设置默认 AI 提供商"""
    try:
        with db_manager.get_session() as session:
            # 先清除所有默认标记
            all_configs = (
                session.query(SystemConfig)
                .filter_by(category=AI_PROVIDER_CATEGORY)
                .all()
            )
            for c in all_configs:
                try:
                    c_data = json.loads(c.value)
                    if c_data.get("is_default", False):
                        c_data["is_default"] = False
                        c.value = json.dumps(c_data, ensure_ascii=False)
                except (json.JSONDecodeError, TypeError):
                    continue

            # 设置目标提供商为默认
            target = (
                session.query(SystemConfig)
                .filter_by(category=AI_PROVIDER_CATEGORY, key=provider_type)
                .first()
            )
            if not target:
                return jsonify({"status": "error", "message": "提供商配置不存在"}), 404

            try:
                target_data = json.loads(target.value)
                target_data["is_default"] = True
                target.value = json.dumps(target_data, ensure_ascii=False)
                target.updated_at = datetime.now()
            except (json.JSONDecodeError, TypeError):
                return jsonify({"status": "error", "message": "配置数据格式错误"}), 500

            log_security_event(
                user=current_user.username,
                action="ai_provider_set_default",
                resource=provider_type,
                result="success",
                message="设置默认 AI 提供商: {}".format(provider_type),
            )

            return jsonify({"status": "ok"})
    except Exception as e:
        logger.error("设置默认 AI 提供商失败: {}".format(str(e)))
        return jsonify(_safe_error_message(e)), 500


@settings_bp.route("/api/ai/providers/<provider_type>/toggle", methods=["POST"])
@admin_required
def api_toggle_ai_provider(provider_type):
    """启用/禁用 AI 提供商"""
    try:
        with db_manager.get_session() as session:
            config = (
                session.query(SystemConfig)
                .filter_by(category=AI_PROVIDER_CATEGORY, key=provider_type)
                .first()
            )
            if not config:
                return jsonify({"status": "error", "message": "提供商配置不存在"}), 404

            try:
                config_data = json.loads(config.value)
                new_status = not config_data.get("is_enabled", True)
                config_data["is_enabled"] = new_status
                config.value = json.dumps(config_data, ensure_ascii=False)
                config.updated_at = datetime.now()
            except (json.JSONDecodeError, TypeError):
                return jsonify({"status": "error", "message": "配置数据格式错误"}), 500

            log_security_event(
                user=current_user.username,
                action="ai_provider_toggle",
                resource=provider_type,
                result="success",
                message="{} AI 提供商: {}".format(
                    "启用" if new_status else "禁用", provider_type
                ),
            )

            return jsonify({"status": "ok", "is_enabled": new_status})
    except Exception as e:
        logger.error("切换 AI 提供商状态失败: {}".format(str(e)))
        return jsonify(_safe_error_message(e)), 500


# ============================================================
# 安全模块管理（超级管理员）
# ============================================================

# 所有可管理的安全模块定义
SECURITY_MODULES = [
    {"id": "firewall", "name": "防火墙", "icon": "fas fa-shield-alt", "category": "边界防护",
     "description": "状态检测防火墙，NAT，端口转发", "critical": True},
    {"id": "ids", "name": "入侵检测 (IDS/IPS)", "icon": "fas fa-crosshairs", "category": "边界防护",
     "description": "网络入侵检测与防御", "critical": True},
    {"id": "waf", "name": "WAF 防护", "icon": "fas fa-globe", "category": "边界防护",
     "description": "Web 应用防火墙", "critical": False},
    {"id": "ddos", "name": "DDoS 防护", "icon": "fas fa-bolt", "category": "边界防护",
     "description": "分布式拒绝服务攻击防护", "critical": True},
    {"id": "dns_filter", "name": "DNS 过滤", "icon": "fas fa-filter", "category": "边界防护",
     "description": "DNS 黑白名单过滤", "critical": False},
    {"id": "vpn", "name": "VPN 服务", "icon": "fas fa-lock", "category": "网络安全",
     "description": "IPSec/SSL VPN 远程接入", "critical": False},
    {"id": "app_control", "name": "应用识别与管控", "icon": "fas fa-fingerprint", "category": "网络安全",
     "description": "深度应用识别 (AppID)", "critical": False},
    {"id": "isolation", "name": "网络隔离", "icon": "fas fa-network-wired", "category": "网络安全",
     "description": "安全区域划分与隔离", "critical": False},
    {"id": "dual_wan", "name": "双出口接入", "icon": "fas fa-random", "category": "网络安全",
     "description": "多 WAN 负载均衡与故障切换", "critical": False},
    {"id": "routing", "name": "动态路由", "icon": "fas fa-route", "category": "网络安全",
     "description": "OSPF/BGP 动态路由协议", "critical": False},
    {"id": "qos", "name": "QoS 管理", "icon": "fas fa-tachometer-alt", "category": "网络安全",
     "description": "流量整形与带宽控制", "critical": False},
    {"id": "honeypot", "name": "蜜罐管理", "icon": "fas fa-spider", "category": "安全审计",
     "description": "诱捕攻击者收集情报", "critical": False},
    {"id": "vuln_scan", "name": "漏洞扫描", "icon": "fas fa-bug", "category": "安全审计",
     "description": "网络漏洞扫描与评估", "critical": False},
    {"id": "compliance", "name": "合规检查", "icon": "fas fa-clipboard-check", "category": "安全审计",
     "description": "CIS/等保2.0 合规检查", "critical": False},
    {"id": "ntconfig", "name": "基线检查", "icon": "fas fa-cogs", "category": "安全审计",
     "description": "网络设备配置基线审计", "critical": False},
    {"id": "siem", "name": "SIEM 中心", "icon": "fas fa-chart-bar", "category": "态势感知",
     "description": "安全信息与事件管理", "critical": False},
    {"id": "content_security", "name": "内容安全", "icon": "fas fa-shield-virus", "category": "内容安全",
     "description": "防病毒/反垃圾/URL过滤/DLP", "critical": False},
    {"id": "rule_update", "name": "规则更新", "icon": "fas fa-sync-alt", "category": "系统",
     "description": "安全规则在线更新", "critical": False},
    {"id": "ha", "name": "高可用 (HA)", "icon": "fas fa-server", "category": "系统",
     "description": "双机热备与故障切换", "critical": False},
]

# 模块状态配置文件
_MODULE_STATUS_FILE = "/etc/gatekeeper/module_status.json"


def _load_module_status() -> dict:
    """加载模块启用/禁用状态"""
    if os.path.exists(_MODULE_STATUS_FILE):
        try:
            with open(_MODULE_STATUS_FILE, "r") as f:
                return json.load(f)
        except Exception:
            pass
    # 默认全部启用
    return {m["id"]: {"enabled": True} for m in SECURITY_MODULES}


def _save_module_status(status: dict):
    """保存模块状态"""
    os.makedirs(os.path.dirname(_MODULE_STATUS_FILE), exist_ok=True)
    with open(_MODULE_STATUS_FILE, "w") as f:
        json.dump(status, f, indent=2, ensure_ascii=False)


@settings_bp.route("/api/modules", methods=["GET"])
@login_required
def api_get_modules():
    """获取所有安全模块状态（所有登录用户可访问）"""
    try:
        status = _load_module_status()
        is_super = current_user.role == UserRole.SUPER_ADMIN
        modules = []
        for m in SECURITY_MODULES:
            ms = status.get(m["id"], {"enabled": True})
            info = {
                "id": m["id"],
                "name": m["name"],
                "category": m["category"],
                "enabled": ms.get("enabled", True),
            }
            # 超管可以看到完整信息
            if is_super:
                info["icon"] = m["icon"]
                info["description"] = m["description"]
                info["critical"] = m["critical"]
                info["disabled_reason"] = ms.get("disabled_reason", "")
                info["disabled_at"] = ms.get("disabled_at", "")
            modules.append(info)
        return jsonify({"status": "ok", "data": modules, "is_super_admin": is_super})
    except Exception as e:
        logger.error("获取模块状态失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


@settings_bp.route("/api/modules/<module_id>/toggle", methods=["POST"])
@super_admin_required
def api_toggle_module(module_id):
    """启用/禁用安全模块"""
    try:
        # 验证模块ID
        valid_ids = [m["id"] for m in SECURITY_MODULES]
        if module_id not in valid_ids:
            return jsonify({"status": "error", "message": "无效的模块ID"}), 400

        data = request.get_json(silent=True) or {}
        enabled = data.get("enabled", True)
        reason = data.get("reason", "")

        status = _load_module_status()
        if module_id not in status:
            status[module_id] = {}

        status[module_id]["enabled"] = enabled
        status[module_id]["disabled_reason"] = reason if not enabled else ""
        status[module_id]["disabled_at"] = datetime.now().isoformat() if not enabled else ""
        _save_module_status(status)

        module_name = next((m["name"] for m in SECURITY_MODULES if m["id"] == module_id), module_id)
        action = "启用" if enabled else "禁用"

        log_security_event(
            user=current_user.username,
            action="module_toggle",
            resource=module_id,
            result="success",
            message="{}模块: {}{}".format(action, module_name, " ({})".format(reason) if reason else ""),
        )

        return jsonify({"status": "ok", "module_id": module_id, "enabled": enabled})
    except Exception as e:
        logger.error("切换模块状态失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


@settings_bp.route("/api/modules/batch-toggle", methods=["POST"])
@super_admin_required
def api_batch_toggle_modules():
    """批量启用/禁用模块"""
    try:
        data = request.get_json(silent=True) or {}
        module_ids = data.get("module_ids", [])
        enabled = data.get("enabled", True)

        status = _load_module_status()
        valid_ids = [m["id"] for m in SECURITY_MODULES]
        updated = []

        for mid in module_ids:
            if mid in valid_ids:
                if mid not in status:
                    status[mid] = {}
                status[mid]["enabled"] = enabled
                status[mid]["disabled_at"] = datetime.now().isoformat() if not enabled else ""
                updated.append(mid)

        _save_module_status(status)

        log_security_event(
            user=current_user.username,
            action="module_batch_toggle",
            resource=",".join(updated),
            result="success",
            message="批量{} {} 个模块".format("启用" if enabled else "禁用", len(updated)),
        )

        return jsonify({"status": "ok", "updated": updated, "count": len(updated)})
    except Exception as e:
        logger.error("批量切换模块状态失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


@settings_bp.route("/api/users/<int:user_id>/role", methods=["POST"])
@super_admin_required
def api_change_user_role(user_id):
    """修改用户角色（仅超级管理员）"""
    try:
        if current_user.id == user_id:
            return jsonify({"status": "error", "message": "不能修改自己的角色"}), 400

        data = request.get_json(silent=True) or {}
        new_role = data.get("role", "")

        valid_roles = [r.value for r in UserRole]
        if new_role not in valid_roles:
            return jsonify({"status": "error", "message": "无效的角色"}), 400

        with db_manager.get_session() as session:
            user = session.query(User).filter_by(id=user_id).first()
            if not user:
                return jsonify({"status": "error", "message": "用户不存在"}), 404

            old_role = user.role.value
            user.role = UserRole(new_role)
            session.commit()

            log_security_event(
                user=current_user.username,
                action="user_role_change",
                resource=user.username,
                result="success",
                message="角色变更: {} -> {}".format(old_role, new_role),
            )

            return jsonify({"status": "ok", "username": user.username, "role": new_role})
    except Exception as e:
        logger.error("修改用户角色失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


@settings_bp.route("/api/super-admin/check", methods=["GET"])
@login_required
def api_check_super_admin():
    """检查当前用户是否为超级管理员"""
    is_super = current_user.role == UserRole.SUPER_ADMIN
    return jsonify({"status": "ok", "is_super_admin": is_super, "role": current_user.role.value})


@settings_bp.route("/api/ai/test", methods=["POST"])
@admin_required
def api_test_ai_connection():
    """测试 AI 提供商连接"""
    data = request.json if request.is_json else {}
    api_key = data.get("api_key", "").strip()
    api_base = data.get("api_base", "").strip().rstrip("/")
    model = data.get("model", "").strip()
    temperature = data.get("temperature", 0.7)
    max_tokens = data.get("max_tokens", 256)

    if not api_key:
        return jsonify({"status": "error", "message": "缺少 API Key"}), 400
    if not api_base:
        return jsonify({"status": "error", "message": "缺少 API Base URL"}), 400
    if not model:
        return jsonify({"status": "error", "message": "缺少模型名称"}), 400

    try:
        url = "{}/chat/completions".format(api_base)
        headers = {
            "Authorization": "Bearer {}".format(api_key),
            "Content-Type": "application/json",
        }
        payload = {
            "model": model,
            "messages": [{"role": "user", "content": "Hello"}],
            "temperature": temperature,
            "max_tokens": min(max_tokens, 256),
        }

        start_time = time.time()
        response = http_requests.post(
            url, headers=headers, json=payload, timeout=30
        )
        latency_ms = int((time.time() - start_time) * 1000)

        if response.status_code == 200:
            resp_data = response.json()
            reply = ""
            try:
                reply = resp_data["choices"][0]["message"]["content"]
            except (KeyError, IndexError):
                reply = "(响应格式异常)"

            log_security_event(
                user=current_user.username,
                action="ai_provider_test",
                resource=model,
                result="success",
                message="AI 连接测试成功: {}, 延迟: {}ms".format(model, latency_ms),
            )

            return jsonify({
                "status": "ok",
                "data": {
                    "response": reply,
                    "latency_ms": latency_ms,
                },
            })
        else:
            error_msg = "HTTP {}".format(response.status_code)
            try:
                err_data = response.json()
                error_msg = err_data.get("error", {}).get(
                    "message", error_msg
                )
            except (json.JSONDecodeError, TypeError, AttributeError):
                if response.text:
                    error_msg = response.text[:200]

            log_security_event(
                user=current_user.username,
                action="ai_provider_test",
                resource=model,
                result="failure",
                message="AI 连接测试失败: {}, 错误: {}".format(model, error_msg),
            )

            return jsonify({
                "status": "error",
                "message": "API 返回错误: {}".format(error_msg),
            })
    except http_requests.Timeout:
        return jsonify({"status": "error", "message": "连接超时（30秒）"})
    except http_requests.ConnectionError:
        return jsonify({"status": "error", "message": "无法连接到 API 服务器，请检查网络和 API Base URL"})
    except Exception as e:
        logger.error("测试 AI 连接失败: {}".format(str(e)))
        return jsonify({"status": "error", "message": "测试失败，请联系管理员"})
