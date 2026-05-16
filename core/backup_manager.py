"""
GateKeeper - 系统配置备份管理模块
提供全量备份、加密、校验、版本管理、定时自动备份、远程同步和恢复功能
"""

import os
import sys
import json
import shutil
import hashlib
import tarfile
import tempfile
import subprocess
from pathlib import Path
from datetime import datetime

import logging

logger = logging.getLogger("gatekeeper.backup")

# ============================================================
# 常量定义
# ============================================================

# 备份存储目录
BACKUP_DIR = Path("/opt/gatekeeper/backups")

# 需要备份的配置目录
CONFIG_DIRS = [
    Path("/opt/gatekeeper/config/"),
    Path("/etc/gatekeeper/"),
]

# 需要备份的网络配置文件
NETWORK_FILES = [
    Path("/etc/network/interfaces"),
    Path("/etc/resolv.conf"),
    Path("/etc/hosts"),
    Path("/etc/hostname"),
]

# 防火墙规则导出命令
FIREWALL_EXPORT_CMDS = [
    # iptables 规则
    (["iptables-save"], "iptables_rules"),
    # ip6tables 规则
    (["ip6tables-save"], "ip6tables_rules"),
    # nftables 规则
    (["nft", "list", "ruleset"], "nftables_rules"),
]

# 数据库路径（SQLite）
DB_PATHS = [
    Path("/opt/gatekeeper/data/gatekeeper.db"),
    Path("/opt/gatekeeper/data/gatekeeper.db-wal"),
    Path("/opt/gatekeeper/data/gatekeeper.db-shm"),
]

# 元数据文件名
METADATA_FILE = "backup_metadata.json"

# 加密密钥文件
ENCRYPTION_KEY_FILE = Path("/etc/gatekeeper/backup_encryption.key")

# 自动备份调度配置文件
SCHEDULE_CONFIG_FILE = Path("/etc/gatekeeper/backup_schedule.json")

# 远程同步配置文件
REMOTE_CONFIG_FILE = Path("/etc/gatekeeper/backup_remote.json")


# ============================================================
# 工具函数
# ============================================================

def _ensure_dir(path):
    """确保目录存在"""
    try:
        path.mkdir(parents=True, exist_ok=True)
    except Exception as e:
        logger.error("创建目录失败 {}: {}".format(path, e))


def _compute_file_sha256(filepath):
    """计算文件的 SHA256 校验和"""
    sha256 = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                sha256.update(chunk)
        return sha256.hexdigest()
    except Exception as e:
        logger.error("计算文件校验和失败 {}: {}".format(filepath, e))
        return None


def _get_system_version():
    """获取系统版本号"""
    try:
        sys_path = Path("/opt/gatekeeper/config/settings.py")
        if sys_path.exists():
            import importlib.util
            spec = importlib.util.spec_from_file_location("bkp_settings", str(sys_path))
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            return getattr(mod, "VERSION", "unknown")
    except Exception:
        pass
    try:
        from config.settings import settings
        return settings.version
    except Exception:
        pass
    return "unknown"


def _get_backup_version():
    """获取当前备份版本号（自增）"""
    version_file = BACKUP_DIR / ".backup_version"
    try:
        if version_file.exists():
            with open(version_file, "r") as f:
                v = int(f.read().strip())
            return v + 1
    except Exception:
        pass
    return 1


def _save_backup_version(version):
    """持久化备份版本号"""
    version_file = BACKUP_DIR / ".backup_version"
    try:
        _ensure_dir(BACKUP_DIR)
        with open(version_file, "w") as f:
            f.write(str(version))
    except Exception as e:
        logger.error("保存备份版本号失败: {}".format(e))


def _generate_encryption_key():
    """生成 Fernet 加密密钥"""
    try:
        from cryptography.fernet import Fernet
        return Fernet.generate_key()
    except ImportError:
        logger.error("cryptography 库未安装，无法生成加密密钥")
        return None


def _load_encryption_key():
    """加载加密密钥"""
    if ENCRYPTION_KEY_FILE.exists():
        try:
            with open(ENCRYPTION_KEY_FILE, "rb") as f:
                key = f.read()
            # 验证密钥是否为有效的 Fernet 密钥
            from cryptography.fernet import Fernet
            Fernet(key)
            return key
        except Exception as e:
            logger.warning("加载加密密钥失败: {}".format(e))
    return None


def _save_encryption_key(key):
    """保存加密密钥"""
    try:
        _ensure_dir(ENCRYPTION_KEY_FILE.parent)
        with open(ENCRYPTION_KEY_FILE, "wb") as f:
            f.write(key)
        os.chmod(str(ENCRYPTION_KEY_FILE), 0o600)
    except Exception as e:
        logger.error("保存加密密钥失败: {}".format(e))


def _encrypt_file(filepath, key):
    """使用 Fernet 加密文件，返回加密后的临时文件路径"""
    try:
        from cryptography.fernet import Fernet
        fernet = Fernet(key)

        with open(filepath, "rb") as f:
            data = f.read()

        encrypted = fernet.encrypt(data)

        enc_path = filepath + ".enc"
        with open(enc_path, "wb") as f:
            f.write(encrypted)

        return enc_path
    except ImportError:
        logger.error("cryptography 库未安装")
        return None
    except Exception as e:
        logger.error("加密文件失败: {}".format(e))
        return None


def _decrypt_file(filepath, key):
    """使用 Fernet 解密文件，返回解密后的临时文件路径"""
    try:
        from cryptography.fernet import Fernet
        fernet = Fernet(key)

        with open(filepath, "rb") as f:
            data = f.read()

        decrypted = fernet.decrypt(data)

        dec_path = filepath + ".dec"
        with open(dec_path, "wb") as f:
            f.write(decrypted)

        return dec_path
    except ImportError:
        logger.error("cryptography 库未安装")
        return None
    except Exception as e:
        logger.error("解密文件失败: {}".format(e))
        return None


# ============================================================
# 备份管理器
# ============================================================

class BackupManager(object):
    """系统配置备份管理器"""

    def __init__(self):
        _ensure_dir(BACKUP_DIR)

    # ----------------------------------------------------------
    # 创建备份
    # ----------------------------------------------------------
    def create_backup(self, encrypt=False, password=None, description=""):
        """
        创建全量备份

        Args:
            encrypt: 是否加密
            password: 加密密码（为 None 时自动生成）
            description: 备份描述

        Returns:
            dict: {"status": "ok", "data": {...}} 或 {"status": "error", "message": "..."}
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = "gatekeeper_backup_{}.tar.gz".format(timestamp)
        backup_path = BACKUP_DIR / filename

        # 临时工作目录
        tmp_dir = None
        try:
            tmp_dir = Path(tempfile.mkdtemp(prefix="gk_backup_"))
            staging_dir = tmp_dir / "backup_staging"
            staging_dir.mkdir()

            # 1. 备份数据库文件
            self._backup_database(staging_dir)

            # 2. 备份系统配置文件
            self._backup_config_dirs(staging_dir)

            # 3. 备份网络配置
            self._backup_network_config(staging_dir)

            # 4. 备份防火墙规则
            self._backup_firewall_rules(staging_dir)

            # 5. 计算各文件校验和（备份前验证源文件完整性）
            checksums = {}
            for root, dirs, files in os.walk(str(staging_dir)):
                for fname in files:
                    fpath = Path(root) / fname
                    cs = _compute_file_sha256(fpath)
                    if cs:
                        rel = str(fpath.relative_to(staging_dir))
                        checksums[rel] = cs

            # 6. 生成元数据
            version = _get_backup_version()
            metadata = {
                "version": version,
                "system_version": _get_system_version(),
                "timestamp": datetime.now().isoformat(),
                "filename": filename,
                "description": description,
                "encrypted": False,
                "checksums": checksums,
                "created_by": "system",
            }

            metadata_path = staging_dir / METADATA_FILE
            with open(metadata_path, "w", encoding="utf-8") as f:
                json.dump(metadata, f, indent=2, ensure_ascii=False)

            # 7. 打包为 tar.gz
            with tarfile.open(str(backup_path), "w:gz") as tar:
                tar.add(str(staging_dir), arcname="gatekeeper_backup")

            # 8. 加密（可选）
            encryption_key = None
            if encrypt:
                encryption_key = self._handle_encryption(backup_path, password)
                if encryption_key is None:
                    # 加密失败，删除备份文件
                    if backup_path.exists():
                        backup_path.unlink()
                    return {
                        "status": "error",
                        "message": "备份加密失败，请检查 cryptography 库是否已安装",
                    }
                metadata["encrypted"] = True
                # 更新元数据中的加密标记
                # 重新打包元数据（加密后原始 tar 已被替换）
                # 将更新后的元数据追加到加密文件旁边
                meta_only_path = backup_path.parent / (filename + ".meta")
                with open(meta_only_path, "w", encoding="utf-8") as f:
                    json.dump(metadata, f, indent=2, ensure_ascii=False)

            # 9. 计算最终备份文件的 SHA256
            final_checksum = _compute_file_sha256(backup_path)
            metadata["sha256"] = final_checksum

            # 保存最终元数据
            meta_final_path = backup_path.parent / (filename + ".meta")
            with open(meta_final_path, "w", encoding="utf-8") as f:
                json.dump(metadata, f, indent=2, ensure_ascii=False)

            # 保存备份版本号
            _save_backup_version(version)

            file_size = backup_path.stat().st_size

            logger.info("备份创建成功: {}, 大小: {} bytes, 加密: {}".format(
                filename, file_size, encrypt
            ))

            return {
                "status": "ok",
                "data": {
                    "filename": filename,
                    "size": file_size,
                    "sha256": final_checksum,
                    "version": version,
                    "timestamp": metadata["timestamp"],
                    "encrypted": encrypt,
                    "description": description,
                },
            }

        except Exception as e:
            logger.error("创建备份失败: {}".format(e), exc_info=True)
            # 清理可能残留的文件
            if backup_path.exists():
                try:
                    backup_path.unlink()
                except Exception:
                    pass
            return {
                "status": "error",
                "message": "创建备份失败: {}".format(str(e)),
            }
        finally:
            # 清理临时目录
            if tmp_dir and tmp_dir.exists():
                try:
                    shutil.rmtree(str(tmp_dir), ignore_errors=True)
                except Exception:
                    pass

    def _handle_encryption(self, backup_path, password):
        """
        处理备份加密

        Returns:
            bytes: 加密密钥，失败返回 None
        """
        # 获取或生成密钥
        if password:
            # 使用用户提供的密码派生 Fernet 密钥
            try:
                import base64
                from cryptography.fernet import Fernet
                from cryptography.hazmat.primitives import hashes
                from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

                salt = os.urandom(16)
                kdf = PBKDF2HMAC(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=salt,
                    iterations=480000,
                )
                key = base64.urlsafe_b64encode(kdf.derive(password.encode("utf-8")))
                _save_encryption_key(key)
            except Exception as e:
                logger.error("从密码派生密钥失败: {}".format(e))
                return None
        else:
            # 自动生成密钥
            key = _load_encryption_key()
            if key is None:
                key = _generate_encryption_key()
                if key is None:
                    return None
                _save_encryption_key(key)

        # 加密备份文件
        enc_path = _encrypt_file(backup_path, key)
        if enc_path is None:
            return None

        try:
            # 用加密文件替换原始文件
            shutil.move(str(enc_path), str(backup_path))
            return key
        except Exception as e:
            logger.error("替换加密文件失败: {}".format(e))
            if enc_path and Path(enc_path).exists():
                try:
                    Path(enc_path).unlink()
                except Exception:
                    pass
            return None

    def _backup_database(self, staging_dir):
        """备份数据库文件"""
        db_dir = staging_dir / "database"
        db_dir.mkdir()

        # 尝试使用 SQLite 在线备份 API（更安全）
        try:
            import sqlite3
            primary_db = Path("/opt/gatekeeper/data/gatekeeper.db")
            if primary_db.exists():
                backup_db = db_dir / "gatekeeper.db"
                conn = sqlite3.connect(str(primary_db))
                bkp_conn = sqlite3.connect(str(backup_db))
                conn.backup(bkp_conn)
                bkp_conn.close()
                conn.close()
                logger.info("数据库在线备份完成")
                return
        except Exception as e:
            logger.warning("SQLite 在线备份失败，回退到文件复制: {}".format(e))

        # 回退：直接复制数据库文件
        for db_path in DB_PATHS:
            if db_path.exists():
                try:
                    shutil.copy2(str(db_path), str(db_dir / db_path.name))
                except Exception as e:
                    logger.error("复制数据库文件失败 {}: {}".format(db_path, e))

    def _backup_config_dirs(self, staging_dir):
        """备份系统配置目录"""
        config_dir = staging_dir / "config"
        config_dir.mkdir()

        for cfg_dir in CONFIG_DIRS:
            if cfg_dir.exists():
                dest = config_dir / cfg_dir.name
                try:
                    shutil.copytree(str(cfg_dir), str(dest), ignore=shutil.ignore_patterns("*.pyc", "__pycache__"))
                except Exception as e:
                    logger.error("复制配置目录失败 {}: {}".format(cfg_dir, e))

    def _backup_network_config(self, staging_dir):
        """备份网络配置文件"""
        net_dir = staging_dir / "network"
        net_dir.mkdir()

        for net_file in NETWORK_FILES:
            if net_file.exists():
                try:
                    shutil.copy2(str(net_file), str(net_dir / net_file.name))
                except Exception as e:
                    logger.error("复制网络配置失败 {}: {}".format(net_file, e))

    def _backup_firewall_rules(self, staging_dir):
        """导出防火墙规则"""
        fw_dir = staging_dir / "firewall"
        fw_dir.mkdir()

        for cmd, name in FIREWALL_EXPORT_CMDS:
            try:
                result = subprocess.run(
                    cmd, capture_output=True, text=True, timeout=10
                )
                if result.returncode == 0 and result.stdout.strip():
                    output_file = fw_dir / "{}.txt".format(name)
                    with open(output_file, "w") as f:
                        f.write(result.stdout)
                    logger.info("防火墙规则导出成功: {}".format(name))
            except subprocess.TimeoutExpired:
                logger.warning("防火墙规则导出超时: {}".format(name))
            except FileNotFoundError:
                logger.debug("防火墙工具不存在: {}".format(cmd[0]))
            except Exception as e:
                logger.error("防火墙规则导出失败 {}: {}".format(name, e))

    # ----------------------------------------------------------
    # 备份列表
    # ----------------------------------------------------------
    def list_backups(self):
        """
        获取备份列表

        Returns:
            list: 备份信息列表
        """
        backups = []
        if not BACKUP_DIR.exists():
            return backups

        for f in sorted(BACKUP_DIR.iterdir(), reverse=True):
            if not f.name.endswith(".tar.gz"):
                continue
            if not f.name.startswith("gatekeeper_backup_"):
                continue

            info = {
                "filename": f.name,
                "size": 0,
                "timestamp": "",
                "version": "",
                "description": "",
                "encrypted": False,
                "sha256": "",
            }

            # 尝试读取元数据
            meta_path = BACKUP_DIR / (f.name + ".meta")
            if meta_path.exists():
                try:
                    with open(meta_path, "r", encoding="utf-8") as mf:
                        meta = json.load(mf)
                    info["timestamp"] = meta.get("timestamp", "")
                    info["version"] = str(meta.get("version", ""))
                    info["description"] = meta.get("description", "")
                    info["encrypted"] = meta.get("encrypted", False)
                    info["sha256"] = meta.get("sha256", "")
                except Exception:
                    pass

            try:
                info["size"] = f.stat().st_size
            except Exception:
                pass

            # 如果没有元数据中的时间戳，从文件名解析
            if not info["timestamp"]:
                try:
                    parts = f.stem.replace("gatekeeper_backup_", "")
                    dt = datetime.strptime(parts, "%Y%m%d_%H%M%S")
                    info["timestamp"] = dt.isoformat()
                except Exception:
                    info["timestamp"] = datetime.fromtimestamp(
                        f.stat().st_mtime
                    ).isoformat() if f.exists() else ""

            backups.append(info)

        return backups

    # ----------------------------------------------------------
    # 删除备份
    # ----------------------------------------------------------
    def delete_backup(self, filename):
        """
        删除备份文件及其元数据

        Args:
            filename: 备份文件名

        Returns:
            dict: 操作结果
        """
        # 安全检查：防止路径遍历
        safe_name = os.path.basename(filename)
        if safe_name != filename or ".." in filename:
            return {"status": "error", "message": "无效的文件名"}

        if not safe_name.startswith("gatekeeper_backup_") or not safe_name.endswith(".tar.gz"):
            return {"status": "error", "message": "无效的备份文件名"}

        backup_path = BACKUP_DIR / safe_name
        meta_path = BACKUP_DIR / (safe_name + ".meta")

        deleted = False
        if backup_path.exists():
            try:
                backup_path.unlink()
                deleted = True
            except Exception as e:
                return {"status": "error", "message": "删除备份文件失败: {}".format(e)}

        if meta_path.exists():
            try:
                meta_path.unlink()
            except Exception:
                pass

        if deleted:
            logger.info("备份已删除: {}".format(safe_name))
            return {"status": "ok", "message": "备份已删除"}
        else:
            return {"status": "error", "message": "备份文件不存在"}

    # ----------------------------------------------------------
    # 下载备份
    # ----------------------------------------------------------
    def get_backup_path(self, filename):
        """
        获取备份文件的绝对路径

        Args:
            filename: 备份文件名

        Returns:
            Path or None
        """
        safe_name = os.path.basename(filename)
        if safe_name != filename or ".." in filename:
            return None
        if not safe_name.startswith("gatekeeper_backup_") or not safe_name.endswith(".tar.gz"):
            return None

        backup_path = BACKUP_DIR / safe_name
        if backup_path.exists():
            return backup_path
        return None

    # ----------------------------------------------------------
    # 上传备份
    # ----------------------------------------------------------
    def upload_backup(self, file_obj, description=""):
        """
        上传备份文件到备份目录

        Args:
            file_obj: 文件对象（Flask request.files 中的文件）
            description: 备份描述

        Returns:
            dict: 操作结果
        """
        if not file_obj or not file_obj.filename:
            return {"status": "error", "message": "未选择文件"}

        filename = file_obj.filename
        safe_name = os.path.basename(filename)

        # 验证文件扩展名
        if not (safe_name.endswith(".tar.gz") or safe_name.endswith(".tgz")):
            return {"status": "error", "message": "仅支持 .tar.gz 格式的备份文件"}

        # 如果文件名不符合命名规范，重命名
        if not safe_name.startswith("gatekeeper_backup_"):
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            safe_name = "gatekeeper_backup_{}_uploaded.tar.gz".format(timestamp)

        dest_path = BACKUP_DIR / safe_name
        if dest_path.exists():
            return {"status": "error", "message": "同名备份文件已存在"}

        try:
            file_obj.save(str(dest_path))

            # 计算校验和
            sha256 = _compute_file_sha256(dest_path)

            # 生成元数据
            meta = {
                "version": _get_backup_version(),
                "system_version": "uploaded",
                "timestamp": datetime.now().isoformat(),
                "filename": safe_name,
                "description": description or "上传的备份",
                "encrypted": False,
                "sha256": sha256,
                "created_by": "upload",
            }

            meta_path = BACKUP_DIR / (safe_name + ".meta")
            with open(meta_path, "w", encoding="utf-8") as f:
                json.dump(meta, f, indent=2, ensure_ascii=False)

            logger.info("备份上传成功: {}".format(safe_name))
            return {
                "status": "ok",
                "message": "备份上传成功",
                "data": {
                    "filename": safe_name,
                    "size": dest_path.stat().st_size,
                },
            }
        except Exception as e:
            logger.error("上传备份失败: {}".format(e))
            if dest_path.exists():
                try:
                    dest_path.unlink()
                except Exception:
                    pass
            return {"status": "error", "message": "上传备份失败: {}".format(str(e))}

    # ----------------------------------------------------------
    # 恢复备份
    # ----------------------------------------------------------
    def restore_backup(self, filename, password=None):
        """
        从备份恢复系统配置

        Args:
            filename: 备份文件名
            password: 解密密码（如果备份是加密的）

        Returns:
            dict: 操作结果
        """
        safe_name = os.path.basename(filename)
        if safe_name != filename or ".." in filename:
            return {"status": "error", "message": "无效的文件名"}

        backup_path = BACKUP_DIR / safe_name
        if not backup_path.exists():
            return {"status": "error", "message": "备份文件不存在"}

        # 读取元数据
        meta_path = BACKUP_DIR / (safe_name + ".meta")
        metadata = None
        if meta_path.exists():
            try:
                with open(meta_path, "r", encoding="utf-8") as f:
                    metadata = json.load(f)
            except Exception:
                pass

        # 版本兼容性检查
        if metadata:
            compat = self._check_compatibility(metadata)
            if not compat["compatible"]:
                return {
                    "status": "error",
                    "message": "版本不兼容: {}".format(compat.get("reason", "未知原因")),
                }

        # 恢复前自动备份当前状态
        pre_backup_result = self.create_backup(
            encrypt=False,
            description="恢复前自动备份 (restore: {})".format(safe_name)
        )
        if pre_backup_result.get("status") != "ok":
            logger.warning("恢复前自动备份失败，继续恢复: {}".format(
                pre_backup_result.get("message", "")
            ))

        # 解密（如果需要）
        work_file = backup_path
        tmp_decrypt = None
        is_encrypted = metadata.get("encrypted", False) if metadata else False

        if is_encrypted:
            key = self._get_decrypt_key(password)
            if key is None:
                return {"status": "error", "message": "无法获取解密密钥，请提供正确的密码"}
            tmp_decrypt = _decrypt_file(backup_path, key)
            if tmp_decrypt is None:
                return {"status": "error", "message": "解密失败，请检查密码是否正确"}
            work_file = Path(tmp_decrypt)

        # 验证校验和
        if metadata and metadata.get("sha256"):
            if not is_encrypted:
                current_sha256 = _compute_file_sha256(work_file)
                if current_sha256 != metadata["sha256"]:
                    return {
                        "status": "error",
                        "message": "备份文件校验和不匹配，文件可能已损坏",
                    }

        # 执行恢复
        tmp_extract = None
        try:
            tmp_extract = Path(tempfile.mkdtemp(prefix="gk_restore_"))

            # 解压
            with tarfile.open(str(work_file), "r:gz") as tar:
                tar.extractall(str(tmp_extract))

            # 查找备份内容根目录
            content_root = None
            for item in tmp_extract.iterdir():
                if item.is_dir():
                    content_root = item
                    break

            if content_root is None:
                return {"status": "error", "message": "备份文件内容格式无效"}

            # 恢复数据库
            self._restore_database(content_root)

            # 恢复配置文件
            self._restore_config(content_root)

            # 恢复网络配置
            self._restore_network(content_root)

            # 恢复防火墙规则
            self._restore_firewall(content_root)

            logger.info("备份恢复成功: {}".format(safe_name))
            return {
                "status": "ok",
                "message": "备份恢复成功，建议重启服务以使配置生效",
                "data": {
                    "filename": safe_name,
                    "pre_backup": pre_backup_result.get("data", {}).get("filename", ""),
                },
            }

        except Exception as e:
            logger.error("恢复备份失败: {}".format(e), exc_info=True)
            return {"status": "error", "message": "恢复备份失败: {}".format(str(e))}
        finally:
            # 清理临时文件
            if tmp_decrypt and Path(tmp_decrypt).exists():
                try:
                    Path(tmp_decrypt).unlink()
                except Exception:
                    pass
            if tmp_extract and tmp_extract.exists():
                try:
                    shutil.rmtree(str(tmp_extract), ignore_errors=True)
                except Exception:
                    pass

    def _get_decrypt_key(self, password):
        """获取解密密钥"""
        # 优先使用提供的密码
        if password:
            try:
                import base64
                from cryptography.hazmat.primitives import hashes
                from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

                # 尝试使用保存的密钥文件中的 salt
                key = _load_encryption_key()
                if key:
                    return key
            except Exception:
                pass

            # 使用密码派生密钥
            try:
                import base64
                from cryptography.hazmat.primitives import hashes
                from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

                salt = os.urandom(16)
                kdf = PBKDF2HMAC(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=salt,
                    iterations=480000,
                )
                return base64.urlsafe_b64encode(kdf.derive(password.encode("utf-8")))
            except Exception as e:
                logger.error("密码派生密钥失败: {}".format(e))
                return None

        # 尝试使用已保存的密钥
        return _load_encryption_key()

    def _check_compatibility(self, metadata):
        """
        检查备份版本兼容性

        Args:
            metadata: 备份元数据

        Returns:
            dict: {"compatible": bool, "reason": str}
        """
        current_version = _get_system_version()

        if current_version == "unknown":
            return {"compatible": True, "reason": ""}

        backup_version = metadata.get("system_version", "unknown")

        # 主版本号相同则兼容
        try:
            current_major = current_version.split(".")[0]
            backup_major = backup_version.split(".")[0]
            if current_major == backup_major:
                return {"compatible": True, "reason": ""}
            else:
                return {
                    "compatible": False,
                    "reason": "主版本号不兼容: 备份版本 {}, 当前版本 {}".format(
                        backup_version, current_version
                    ),
                }
        except Exception:
            return {"compatible": True, "reason": ""}

    def _restore_database(self, content_root):
        """恢复数据库"""
        db_dir = content_root / "database"
        if not db_dir.exists():
            logger.warning("备份中未包含数据库目录")
            return

        target_dir = Path("/opt/gatekeeper/data")
        _ensure_dir(target_dir)

        for db_file in db_dir.iterdir():
            if db_file.is_file():
                try:
                    target = target_dir / db_file.name
                    # 先停止可能占用数据库的进程（仅复制文件）
                    shutil.copy2(str(db_file), str(target))
                    logger.info("数据库文件已恢复: {}".format(db_file.name))
                except Exception as e:
                    logger.error("恢复数据库文件失败 {}: {}".format(db_file.name, e))

    def _restore_config(self, content_root):
        """恢复配置文件"""
        config_dir = content_root / "config"
        if not config_dir.exists():
            logger.warning("备份中未包含配置目录")
            return

        for sub_dir in config_dir.iterdir():
            if sub_dir.is_dir():
                target = Path("/opt/gatekeeper/config") / sub_dir.name
                if target.exists():
                    try:
                        shutil.rmtree(str(target))
                    except Exception:
                        pass
                try:
                    shutil.copytree(str(sub_dir), str(target))
                    logger.info("配置目录已恢复: {}".format(sub_dir.name))
                except Exception as e:
                    logger.error("恢复配置目录失败 {}: {}".format(sub_dir.name, e))

            # 也检查 /etc/gatekeeper/ 目录
            etc_target = Path("/etc/gatekeeper") / sub_dir.name
            if etc_target.parent.exists():
                try:
                    if etc_target.exists():
                        shutil.rmtree(str(etc_target))
                    shutil.copytree(str(sub_dir), str(etc_target))
                    logger.info("系统配置已恢复: /etc/gatekeeper/{}".format(sub_dir.name))
                except Exception as e:
                    logger.error("恢复系统配置失败: {}".format(e))

    def _restore_network(self, content_root):
        """恢复网络配置"""
        net_dir = content_root / "network"
        if not net_dir.exists():
            logger.warning("备份中未包含网络配置")
            return

        for net_file in net_dir.iterdir():
            if net_file.is_file():
                target = None
                if net_file.name == "interfaces":
                    target = Path("/etc/network/interfaces")
                elif net_file.name == "resolv.conf":
                    target = Path("/etc/resolv.conf")
                elif net_file.name == "hosts":
                    target = Path("/etc/hosts")
                elif net_file.name == "hostname":
                    target = Path("/etc/hostname")

                if target:
                    try:
                        shutil.copy2(str(net_file), str(target))
                        logger.info("网络配置已恢复: {}".format(net_file.name))
                    except Exception as e:
                        logger.error("恢复网络配置失败 {}: {}".format(net_file.name, e))

    def _restore_firewall(self, content_root):
        """恢复防火墙规则"""
        fw_dir = content_root / "firewall"
        if not fw_dir.exists():
            logger.warning("备份中未包含防火墙规则")
            return

        restore_cmds = {
            "iptables_rules.txt": ["iptables-restore"],
            "ip6tables_rules.txt": ["ip6tables-restore"],
            "nftables_rules.txt": ["nft", "-f"],
        }

        for fw_file in fw_dir.iterdir():
            if not fw_file.is_file():
                continue
            cmd = restore_cmds.get(fw_file.name)
            if cmd is None:
                continue
            try:
                with open(fw_file, "r") as f:
                    content = f.read()
                if content.strip():
                    result = subprocess.run(
                        cmd, input=content, capture_output=True, text=True, timeout=15
                    )
                    if result.returncode == 0:
                        logger.info("防火墙规则已恢复: {}".format(fw_file.name))
                    else:
                        logger.error("防火墙规则恢复失败 {}: {}".format(
                            fw_file.name, result.stderr
                        ))
            except Exception as e:
                logger.error("恢复防火墙规则异常 {}: {}".format(fw_file.name, e))

    # ----------------------------------------------------------
    # 定时自动备份
    # ----------------------------------------------------------
    def get_schedule(self):
        """
        获取自动备份计划配置

        Returns:
            dict: 调度配置
        """
        default_config = {
            "enabled": False,
            "cron_expression": "0 2 * * *",
            "cron_description": "每天凌晨 2:00",
            "retain_count": 10,
            "encrypt": False,
        }

        if SCHEDULE_CONFIG_FILE.exists():
            try:
                with open(SCHEDULE_CONFIG_FILE, "r", encoding="utf-8") as f:
                    config = json.load(f)
                default_config.update(config)
            except Exception as e:
                logger.error("读取备份调度配置失败: {}".format(e))

        return default_config

    def set_schedule(self, config):
        """
        设置自动备份计划

        Args:
            config: dict, 包含 enabled, cron_expression, retain_count, encrypt

        Returns:
            dict: 操作结果
        """
        try:
            _ensure_dir(SCHEDULE_CONFIG_FILE.parent)
            with open(SCHEDULE_CONFIG_FILE, "w", encoding="utf-8") as f:
                json.dump(config, f, indent=2, ensure_ascii=False)

            logger.info("自动备份计划已更新: {}".format(config))
            return {"status": "ok", "message": "自动备份计划已保存"}
        except Exception as e:
            logger.error("保存备份调度配置失败: {}".format(e))
            return {"status": "error", "message": "保存失败: {}".format(str(e))}

    def cleanup_old_backups(self, retain_count=10):
        """
        清理旧备份，保留最近 N 份

        Args:
            retain_count: 保留份数

        Returns:
            int: 删除的备份数量
        """
        backups = self.list_backups()
        if len(backups) <= retain_count:
            return 0

        deleted = 0
        for backup in backups[retain_count:]:
            result = self.delete_backup(backup["filename"])
            if result.get("status") == "ok":
                deleted += 1

        if deleted > 0:
            logger.info("已清理 {} 份旧备份，保留最近 {} 份".format(deleted, retain_count))

        return deleted

    # ----------------------------------------------------------
    # 远程同步
    # ----------------------------------------------------------
    def get_remote_config(self):
        """
        获取远程同步配置

        Returns:
            dict: 远程配置
        """
        default_config = {
            "enabled": False,
            "host": "",
            "port": 22,
            "username": "",
            "remote_path": "/opt/gatekeeper/backups/",
            "auth_type": "password",  # password / key
            "use_paramiko": True,
        }

        if REMOTE_CONFIG_FILE.exists():
            try:
                with open(REMOTE_CONFIG_FILE, "r", encoding="utf-8") as f:
                    config = json.load(f)
                default_config.update(config)
            except Exception as e:
                logger.error("读取远程同步配置失败: {}".format(e))

        return default_config

    def set_remote_config(self, config):
        """
        设置远程同步配置

        Args:
            config: dict

        Returns:
            dict: 操作结果
        """
        try:
            _ensure_dir(REMOTE_CONFIG_FILE.parent)
            with open(REMOTE_CONFIG_FILE, "w", encoding="utf-8") as f:
                json.dump(config, f, indent=2, ensure_ascii=False)
            return {"status": "ok", "message": "远程同步配置已保存"}
        except Exception as e:
            return {"status": "error", "message": "保存失败: {}".format(str(e))}

    def test_remote_connection(self, config=None):
        """
        测试远程服务器连接

        Args:
            config: 远程配置（为 None 时使用已保存的配置）

        Returns:
            dict: 测试结果
        """
        if config is None:
            config = self.get_remote_config()

        host = config.get("host", "")
        port = config.get("port", 22)
        username = config.get("username", "")
        password = config.get("password", "")
        key_path = config.get("key_path", "")
        use_paramiko = config.get("use_paramiko", True)

        if not host or not username:
            return {"status": "error", "message": "缺少主机地址或用户名"}

        if use_paramiko:
            return self._test_ssh_paramiko(host, port, username, password, key_path)
        else:
            return self._test_ssh_subprocess(host, port, username, password, key_path)

    def _test_ssh_paramiko(self, host, port, username, password, key_path):
        """使用 paramiko 测试 SSH 连接"""
        try:
            import paramiko

            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            connect_kwargs = {
                "hostname": host,
                "port": int(port),
                "username": username,
                "timeout": 10,
            }

            if key_path:
                key_path = os.path.expanduser(key_path)
                if os.path.exists(key_path):
                    connect_kwargs["key_filename"] = key_path
                else:
                    return {"status": "error", "message": "SSH 密钥文件不存在: {}".format(key_path)}
            elif password:
                connect_kwargs["password"] = password

            client.connect(**connect_kwargs)
            client.close()

            return {"status": "ok", "message": "远程连接测试成功"}
        except ImportError:
            return {"status": "error", "message": "paramiko 未安装，请安装: pip install paramiko"}
        except paramiko.AuthenticationException:
            return {"status": "error", "message": "认证失败，请检查用户名和密码/密钥"}
        except paramiko.SSHException as e:
            return {"status": "error", "message": "SSH 连接失败: {}".format(str(e))}
        except Exception as e:
            return {"status": "error", "message": "连接失败: {}".format(str(e))}

    def _test_ssh_subprocess(self, host, port, username, password, key_path):
        """使用 ssh 命令测试连接"""
        try:
            cmd = [
                "ssh",
                "-o", "StrictHostKeyChecking=no",
                "-o", "ConnectTimeout=10",
                "-p", str(port),
            ]
            if key_path:
                cmd.extend(["-i", os.path.expanduser(key_path)])
            cmd.append("{}@{}".format(username, host))
            cmd.append("echo ok")

            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=15,
                input=password if password else ""
            )
            if result.returncode == 0 and "ok" in result.stdout:
                return {"status": "ok", "message": "远程连接测试成功"}
            else:
                return {"status": "error", "message": "SSH 连接失败: {}".format(result.stderr.strip())}
        except subprocess.TimeoutExpired:
            return {"status": "error", "message": "连接超时"}
        except FileNotFoundError:
            return {"status": "error", "message": "ssh 命令不存在"}
        except Exception as e:
            return {"status": "error", "message": "连接失败: {}".format(str(e))}

    def sync_to_remote(self, filename=None, config=None):
        """
        同步备份到远程服务器

        Args:
            filename: 指定备份文件名（None 则同步所有）
            config: 远程配置

        Returns:
            dict: 操作结果
        """
        if config is None:
            config = self.get_remote_config()

        host = config.get("host", "")
        port = config.get("port", 22)
        username = config.get("username", "")
        password = config.get("password", "")
        key_path = config.get("key_path", "")
        remote_path = config.get("remote_path", "/opt/gatekeeper/backups/")
        use_paramiko = config.get("use_paramiko", True)

        if not host or not username:
            return {"status": "error", "message": "远程同步未配置"}

        # 确定要同步的文件
        if filename:
            safe_name = os.path.basename(filename)
            backup_path = BACKUP_DIR / safe_name
            if not backup_path.exists():
                return {"status": "error", "message": "备份文件不存在"}
            files_to_sync = [backup_path]
            # 也同步元数据
            meta_path = BACKUP_DIR / (safe_name + ".meta")
            if meta_path.exists():
                files_to_sync.append(meta_path)
        else:
            files_to_sync = []
            for f in BACKUP_DIR.iterdir():
                if f.name.endswith(".tar.gz") or f.name.endswith(".meta"):
                    files_to_sync.append(f)

        if not files_to_sync:
            return {"status": "error", "message": "没有可同步的备份文件"}

        if use_paramiko:
            return self._sync_sftp(files_to_sync, host, port, username, password, key_path, remote_path)
        else:
            return self._sync_scp(files_to_sync, host, port, username, password, key_path, remote_path)

    def _sync_sftp(self, files, host, port, username, password, key_path, remote_path):
        """使用 SFTP 上传文件"""
        try:
            import paramiko

            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            connect_kwargs = {
                "hostname": host,
                "port": int(port),
                "username": username,
                "timeout": 30,
            }

            if key_path:
                kp = os.path.expanduser(key_path)
                if os.path.exists(kp):
                    connect_kwargs["key_filename"] = kp
                else:
                    return {"status": "error", "message": "SSH 密钥文件不存在"}
            elif password:
                connect_kwargs["password"] = password

            client.connect(**connect_kwargs)
            sftp = client.open_sftp()

            # 确保远程目录存在
            try:
                sftp.stat(remote_path)
            except FileNotFoundError:
                # 尝试创建远程目录
                try:
                    sftp.mkdir(remote_path)
                except Exception:
                    pass

            uploaded = 0
            for local_file in files:
                try:
                    remote_file = remote_path + "/" + local_file.name
                    sftp.put(str(local_file), remote_file)
                    uploaded += 1
                    logger.info("已上传: {} -> {}".format(local_file.name, remote_file))
                except Exception as e:
                    logger.error("上传失败 {}: {}".format(local_file.name, e))

            sftp.close()
            client.close()

            return {
                "status": "ok",
                "message": "已同步 {} 个文件到远程服务器".format(uploaded),
            }
        except ImportError:
            return {"status": "error", "message": "paramiko 未安装"}
        except Exception as e:
            return {"status": "error", "message": "远程同步失败: {}".format(str(e))}

    def _sync_scp(self, files, host, port, username, password, key_path, remote_path):
        """使用 scp 命令上传文件"""
        try:
            uploaded = 0
            for local_file in files:
                cmd = ["scp", "-o", "StrictHostKeyChecking=no", "-P", str(port)]
                if key_path:
                    cmd.extend(["-i", os.path.expanduser(key_path)])
                cmd.append(str(local_file))
                cmd.append("{}@{}:{}".format(username, host, remote_path))

                result = subprocess.run(
                    cmd, capture_output=True, text=True, timeout=120,
                    input=password if password else ""
                )
                if result.returncode == 0:
                    uploaded += 1
                else:
                    logger.error("SCP 上传失败: {}".format(result.stderr))

            if uploaded > 0:
                return {
                    "status": "ok",
                    "message": "已同步 {} 个文件到远程服务器".format(uploaded),
                }
            else:
                return {"status": "error", "message": "所有文件上传失败"}
        except FileNotFoundError:
            return {"status": "error", "message": "scp 命令不存在"}
        except Exception as e:
            return {"status": "error", "message": "远程同步失败: {}".format(str(e))}


# 全局备份管理器实例
backup_manager = BackupManager()
