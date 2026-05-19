"""
GateKeeper - 加密工具
提供密码哈希、Token生成、数据加密等安全工具函数
"""

import os
import hashlib
import hmac
import base64
import binascii
import json
from typing import Optional, Dict, Any

from config.logging_config import get_logger

logger = get_logger("crypto")


# ============================================================
# 密码哈希
# ============================================================

def hash_password(password: str, salt: Optional[str] = None) -> str:
    """
    使用PBKDF2-SHA256对密码进行哈希

    Args:
        password: 明文密码
        salt: 盐值，None表示自动生成

    Returns:
        格式为 "salt:hash" 的字符串
    """
    if salt is None:
        salt = binascii.hexlify(os.urandom(16)).decode("ascii")

    # 使用PBKDF2进行哈希
    hash_value = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        iterations=100000,
        dklen=32,
    )

    return "{}:{}".format(salt, hash_value.hex())


def verify_password(password: str, password_hash: str) -> bool:
    """
    验证密码是否匹配哈希
    支持两种格式：
    - 自定义格式: "salt:hash"
    - Werkzeug格式: "pbkdf2:sha256:iterations$salt$hash"

    Args:
        password: 明文密码
        password_hash: 哈希值

    Returns:
        是否匹配
    """
    try:
        # Werkzeug格式 (pbkdf2:sha256:...)
        if password_hash.startswith("pbkdf2:"):
            from werkzeug.security import check_password_hash
            return check_password_hash(password_hash, password)

        # 自定义格式 (salt:hash)
        salt, hash_value = password_hash.split(":", 1)
        computed_hash = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt.encode("utf-8"),
            iterations=100000,
            dklen=32,
        )
        return hmac.compare_digest(computed_hash.hex(), hash_value)
    except (ValueError, AttributeError):
        return False


# ============================================================
# Token生成
# ============================================================

def generate_token(length: int = 32) -> str:
    """
    生成安全的随机Token

    Args:
        length: Token长度（字节数）

    Returns:
        十六进制Token字符串
    """
    return binascii.hexlify(os.urandom(length)).decode("ascii")


def generate_api_key(prefix: str = "gatekeeper") -> str:
    """
    生成API密钥

    Args:
        prefix: 密钥前缀

    Returns:
        格式为 "prefix_xxxxx" 的API密钥
    """
    token = base64.urlsafe_b64encode(os.urandom(32)).decode("ascii").rstrip("=")
    return "{}_{}".format(prefix, token)


def generate_session_token() -> str:
    """生成会话Token"""
    return base64.urlsafe_b64encode(os.urandom(48)).decode("ascii").rstrip("=")


def generate_csrf_token() -> str:
    """生成CSRF Token"""
    return binascii.hexlify(os.urandom(32)).decode("ascii")


# ============================================================
# 数据加密
# ============================================================

def _get_encryption_key() -> bytes:
    """获取加密密钥
    
    安全修复：如果未设置环境变量，自动生成随机密钥并持久化到文件。
    安全修复：如果cryptography库不可用，直接抛出异常。
    """
    # 检查cryptography库是否可用
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # noqa: F401
    except ImportError:
        raise RuntimeError(
            "cryptography库未安装，无法执行加密操作。"
            "请安装cryptography库: pip install cryptography>=3.4.0"
        )

    import json
    key_file = "/etc/gatekeeper/encryption_key.json"
    
    # 优先从环境变量获取
    key = os.environ.get("GK_ENCRYPTION_KEY")
    if key:
        return hashlib.sha256(key.encode("utf-8")).digest()
    
    # 尝试从持久化文件读取
    try:
        if os.path.exists(key_file):
            with open(key_file, "r") as f:
                data = json.load(f)
                key = data.get("key")
                if key:
                    return hashlib.sha256(key.encode("utf-8")).digest()
    except (IOError, json.JSONDecodeError):
        pass
    
    # 自动生成随机密钥并持久化
    import secrets
    key = secrets.token_hex(32)  # 64 字符随机密钥
    try:
        # 确保父目录权限安全（仅 root 可访问）
        key_dir = os.path.dirname(key_file)
        if key_dir and not os.path.exists(key_dir):
            os.makedirs(key_dir, mode=0o700, exist_ok=True)
        elif key_dir and os.path.exists(key_dir):
            # 确保现有目录权限正确
            os.chmod(key_dir, 0o700)
        with open(key_file, "w") as f:
            json.dump({"key": key, "generated_at": __import__("datetime").datetime.now().isoformat()}, f)
        os.chmod(key_file, 0o600)  # 仅 root 可读写
    except (IOError, PermissionError):
        pass  # 无法持久化时使用内存中的随机密钥
    
    return hashlib.sha256(key.encode("utf-8")).digest()


def encrypt_data(plaintext: str, key: Optional[bytes] = None) -> str:
    """
    使用AES-256-GCM加密数据

    Args:
        plaintext: 明文字符串
        key: 加密密钥，None表示使用默认密钥

    Returns:
        Base64编码的加密数据（格式: nonce+ciphertext+tag）
    """
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from cryptography.hazmat.backends import default_backend
    except ImportError:
        # 回退到简单的XOR加密（不推荐用于生产环境）
        logger.warning("cryptography库未安装，使用简单加密")
        return _simple_encrypt(plaintext)

    if key is None:
        key = _get_encryption_key()

    aesgcm = AESGCM(key)
    nonce = os.urandom(12)  # GCM推荐12字节nonce

    plaintext_bytes = plaintext.encode("utf-8")
    ciphertext = aesgcm.encrypt(nonce, plaintext_bytes, None)

    # 组合 nonce + ciphertext
    encrypted = nonce + ciphertext
    return base64.b64encode(encrypted).decode("utf-8")


def decrypt_data(encrypted_text: str, key: Optional[bytes] = None) -> str:
    """
    使用AES-256-GCM解密数据

    Args:
        encrypted_text: Base64编码的加密数据
        key: 加密密钥

    Returns:
        解密后的明文字符串
    """
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError:
        return _simple_decrypt(encrypted_text)

    if key is None:
        key = _get_encryption_key()

    try:
        encrypted = base64.b64decode(encrypted_text)
        nonce = encrypted[:12]
        ciphertext = encrypted[12:]

        aesgcm = AESGCM(key)
        plaintext_bytes = aesgcm.decrypt(nonce, ciphertext, None)
        return plaintext_bytes.decode("utf-8")
    except Exception as e:
        logger.error("解密失败: {}".format(e))
        raise ValueError("解密失败") from e


def _simple_encrypt(plaintext: str) -> str:
    """简单加密已禁用 - XOR加密不安全，不允许使用"""
    raise RuntimeError(
        "cryptography库未安装，无法执行安全加密。"
        "请安装cryptography库: pip install cryptography>=3.4.0"
    )


def _simple_decrypt(encrypted_text: str) -> str:
    """简单解密已禁用 - XOR解密不安全，不允许使用"""
    raise RuntimeError(
        "cryptography库未安装，无法执行安全解密。"
        "请安装cryptography库: pip install cryptography>=3.4.0"
    )


# ============================================================
# 哈希工具
# ============================================================

def md5_hash(data: str) -> str:
    """计算MD5哈希（用于非安全场景，如数据指纹）"""
    return hashlib.md5(data.encode("utf-8")).hexdigest()


def sha256_hash(data: str) -> str:
    """计算SHA-256哈希"""
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def sha512_hash(data: str) -> str:
    """计算SHA-512哈希"""
    return hashlib.sha512(data.encode("utf-8")).hexdigest()


def file_hash(filepath: str, algorithm: str = "sha256") -> str:
    """
    计算文件哈希

    Args:
        filepath: 文件路径
        algorithm: 哈希算法 (md5/sha1/sha256/sha512)

    Returns:
        哈希值
    """
    hash_func = getattr(hashlib, algorithm, hashlib.sha256)()

    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            hash_func.update(chunk)

    return hash_func.hexdigest()


# ============================================================
# HMAC签名
# ============================================================

def hmac_sign(data: str, secret: str) -> str:
    """
    使用HMAC-SHA256对数据进行签名

    Args:
        data: 要签名的数据
        secret: 密钥

    Returns:
        签名值（十六进制）
    """
    signature = hmac.new(
        secret.encode("utf-8"),
        data.encode("utf-8"),
        hashlib.sha256,
    )
    return signature.hexdigest()


def hmac_verify(data: str, secret: str, signature: str) -> bool:
    """
    验证HMAC签名

    Args:
        data: 原始数据
        secret: 密钥
        signature: 签名值

    Returns:
        签名是否有效
    """
    expected = hmac_sign(data, secret)
    return hmac.compare_digest(expected, signature)
