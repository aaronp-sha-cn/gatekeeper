"""
GateKeeper - 合规检查引擎
提供系统安全合规检查、报告生成和导出功能
支持 CIS Benchmark 和等保2.0 标准
"""

import os
import re
import json
import subprocess
import threading
import uuid
try:
    import paramiko
except ImportError:
    paramiko = None
from datetime import datetime
from typing import Optional, List, Dict, Any

from config.logging_config import get_logger

logger = get_logger("compliance")


# ============================================================
# 数据模型
# ============================================================

class ComplianceCheck:
    """合规检查项"""

    def __init__(self, category: str, name: str, description: str,
                 severity: str = "medium", status: str = "not_checked",
                 result_detail: str = "", remediation: str = ""):
        self.id = str(uuid.uuid4())[:8]
        self.category = category
        self.name = name
        self.description = description
        self.severity = severity  # info / low / medium / high / critical
        self.status = status      # pass / fail / warning / not_checked
        self.result_detail = result_detail
        self.remediation = remediation
        self.checked_at = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "category": self.category,
            "name": self.name,
            "description": self.description,
            "severity": self.severity,
            "status": self.status,
            "result_detail": self.result_detail,
            "remediation": self.remediation,
            "checked_at": self.checked_at.isoformat() if self.checked_at else None,
        }


class ComplianceReport:
    """合规报告"""

    def __init__(self, title: str, standard: str = "cis"):
        self.id = str(uuid.uuid4())[:12]
        self.title = title
        self.standard = standard  # cis / djcp / custom
        self.total_checks = 0
        self.passed = 0
        self.failed = 0
        self.warnings = 0
        self.score = 0
        self.created_at = datetime.now()
        self.checks: List[ComplianceCheck] = []

    def add_check(self, check: ComplianceCheck):
        """添加检查项并更新统计"""
        self.checks.append(check)
        self.total_checks += 1
        if check.status == "pass":
            self.passed += 1
        elif check.status == "fail":
            self.failed += 1
        elif check.status == "warning":
            self.warnings += 1

    def calculate_score(self) -> int:
        """计算合规分数 (0-100)"""
        if self.total_checks == 0:
            self.score = 0
            return 0

        # 权重: pass=100, warning=50, fail=0, not_checked=0
        total_weight = 0
        for check in self.checks:
            if check.status == "pass":
                total_weight += 100
            elif check.status == "warning":
                total_weight += 50
            # fail 和 not_checked 不加分

        # 按严重度加权: critical=3, high=2, medium=1, low=0.5, info=0.3
        severity_weight_map = {
            "critical": 3, "high": 2, "medium": 1, "low": 0.5, "info": 0.3
        }
        max_weight = sum(
            100 * severity_weight_map.get(c.severity, 1)
            for c in self.checks
        )
        actual_weight = sum(
            (100 if c.status == "pass" else 50 if c.status == "warning" else 0)
            * severity_weight_map.get(c.severity, 1)
            for c in self.checks
        )

        if max_weight > 0:
            self.score = int(actual_weight / max_weight * 100)
        else:
            self.score = 0

        return self.score

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "standard": self.standard,
            "standard_name": self._get_standard_name(),
            "total_checks": self.total_checks,
            "passed": self.passed,
            "failed": self.failed,
            "warnings": self.warnings,
            "not_checked": self.total_checks - self.passed - self.failed - self.warnings,
            "score": self.score,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "checks": [c.to_dict() for c in self.checks],
        }

    def _get_standard_name(self) -> str:
        names = {"cis": "CIS Benchmark", "djcp": "等保2.0", "custom": "自定义"}
        return names.get(self.standard, self.standard)


# ============================================================
# 合规检查器
# ============================================================

class ComplianceChecker:
    """合规检查器"""

    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
                cls._instance._initialized = False
            return cls._instance

    def __init__(self):
        if self._initialized:
            return
        self._initialized = True
        self._reports: List[ComplianceReport] = []
        self._current_checks: List[ComplianceCheck] = []
        self._is_checking = False
        logger.info("合规检查器初始化完成")

    # ---- 公共方法 ----

    def run_full_check(self, standard: str = "cis") -> ComplianceReport:
        """
        执行完整合规检查

        Args:
            standard: 检查标准 (cis / djcp)

        Returns:
            ComplianceReport
        """
        if self._is_checking:
            raise RuntimeError("合规检查正在进行中，请稍后再试")

        self._is_checking = True
        standard_name = "CIS Benchmark" if standard == "cis" else "等保2.0"
        report = ComplianceReport(
            title="合规检查报告 - {}".format(
                datetime.now().strftime("%Y-%m-%d %H:%M")
            ),
            standard=standard,
        )

        try:
            categories = [
                "系统安全", "网络安全", "用户管理",
                "日志审计", "数据保护", "服务安全",
            ]

            for category in categories:
                checks = self._run_category_checks(category, standard)
                for check in checks:
                    report.add_check(check)

            report.calculate_score()
            self._reports.append(report)
            logger.info(
                "合规检查完成: 标准={}, 分数={}, 通过={}, 失败={}, 警告={}".format(
                    standard_name, report.score, report.passed,
                    report.failed, report.warnings,
                )
            )

        except Exception as e:
            logger.error("合规检查异常: {}".format(e))
        finally:
            self._is_checking = False

        return report

    def run_category_check(self, category: str,
                           standard: str = "cis") -> List[ComplianceCheck]:
        """
        执行单类别检查

        Args:
            category: 检查类别
            standard: 检查标准

        Returns:
            检查项列表
        """
        return self._run_category_checks(category, standard)

    def get_checks(self, category: str = None,
                   status: str = None) -> List[Dict[str, Any]]:
        """
        获取最近一次检查结果

        Args:
            category: 按类别过滤
            status: 按状态过滤

        Returns:
            检查项字典列表
        """
        if not self._reports:
            return []

        checks = self._reports[-1].checks
        if category:
            checks = [c for c in checks if c.category == category]
        if status:
            checks = [c for c in checks if c.status == status]

        return [c.to_dict() for c in checks]

    def get_reports(self) -> List[Dict[str, Any]]:
        """获取历史报告列表"""
        return [r.to_dict() for r in reversed(self._reports)]

    def get_latest_report(self) -> Optional[Dict[str, Any]]:
        """获取最新报告"""
        if self._reports:
            return self._reports[-1].to_dict()
        return None

    def get_score(self) -> int:
        """获取当前合规分数"""
        if self._reports:
            return self._reports[-1].score
        return 0

    def export_report(self, report_id: str,
                      format: str = "json") -> Optional[str]:
        """
        导出报告

        Args:
            report_id: 报告ID
            format: 导出格式 (json / csv / html)

        Returns:
            导出内容字符串，失败返回None
        """
        report = None
        for r in self._reports:
            if r.id == report_id:
                report = r
                break

        if not report:
            logger.error("报告不存在: {}".format(report_id))
            return None

        if format == "json":
            return self._export_json(report)
        elif format == "csv":
            return self._export_csv(report)
        elif format == "html":
            return self._export_html(report)
        else:
            logger.error("不支持的导出格式: {}".format(format))
            return None

    def is_checking(self) -> bool:
        """检查是否正在进行合规检查"""
        return self._is_checking

    # ---- 分类检查实现 ----

    def _run_category_checks(self, category: str,
                             standard: str) -> List[ComplianceCheck]:
        """执行指定类别的所有检查"""
        check_methods = {
            "系统安全": self._check_system_security,
            "网络安全": self._check_network_security,
            "用户管理": self._check_user_management,
            "日志审计": self._check_log_audit,
            "数据保护": self._check_data_protection,
            "服务安全": self._check_service_security,
        }

        method = check_methods.get(category)
        if method:
            try:
                return method(standard)
            except Exception as e:
                logger.error("类别[{}]检查异常: {}".format(category, e))
                return []

        logger.warning("未知检查类别: {}".format(category))
        return []

    # ---- 系统安全检查 ----

    def _check_system_security(self, standard: str) -> List[ComplianceCheck]:
        """系统安全检查（10项）"""
        checks = []
        now = datetime.now()

        # 1. 防火墙状态检查
        check = ComplianceCheck(
            category="系统安全",
            name="防火墙状态检查",
            description="检查系统防火墙是否已启用",
            severity="high",
            remediation="启用防火墙: sudo ufw enable 或 sudo systemctl enable --now firewalld",
        )
        try:
            result = subprocess.run(
                ["ufw", "status"], capture_output=True, text=True, timeout=10
            )
            if "active" in result.stdout.lower() or "Status: active" in result.stdout:
                check.status = "pass"
                check.result_detail = "UFW防火墙已启用"
            else:
                # 尝试检查 firewalld
                result2 = subprocess.run(
                    ["systemctl", "is-active", "firewalld"],
                    capture_output=True, text=True, timeout=10,
                )
                if "active" in result2.stdout.strip():
                    check.status = "pass"
                    check.result_detail = "firewalld防火墙已启用"
                else:
                    check.status = "fail"
                    check.result_detail = "防火墙未启用"
        except FileNotFoundError:
            check.status = "warning"
            check.result_detail = "未找到UFW/firewalld命令"
        except Exception as e:
            check.status = "warning"
            check.result_detail = "检查失败: {}".format(str(e))
        check.checked_at = now
        checks.append(check)

        # 2. SELinux/AppArmor状态
        check = ComplianceCheck(
            category="系统安全",
            name="SELinux/AppArmor状态",
            description="检查SELinux或AppArmor安全模块是否启用",
            severity="medium",
            remediation="启用AppArmor: sudo systemctl enable apparmor; 启用SELinux: 编辑/etc/selinux/config设置SELINUX=enforcing",
        )
        try:
            # 检查 AppArmor
            result = subprocess.run(
                ["aa-status"], capture_output=True, text=True, timeout=10,
            )
            if result.returncode == 0 and "profiles are loaded" in result.stdout:
                check.status = "pass"
                check.result_detail = "AppArmor已启用并加载了安全配置文件"
            else:
                # 检查 SELinux
                result2 = subprocess.run(
                    ["getenforce"], capture_output=True, text=True, timeout=10,
                )
                if "Enforcing" in result2.stdout.strip():
                    check.status = "pass"
                    check.result_detail = "SELinux处于Enforcing模式"
                else:
                    check.status = "warning"
                    check.result_detail = "SELinux/AppArmor未启用或未处于强制模式"
        except FileNotFoundError:
            check.status = "warning"
            check.result_detail = "未找到安全模块管理命令"
        except Exception as e:
            check.status = "warning"
            check.result_detail = "检查失败: {}".format(str(e))
        check.checked_at = now
        checks.append(check)

        # 3. 自动更新配置
        check = ComplianceCheck(
            category="系统安全",
            name="自动更新配置",
            description="检查系统是否配置了自动安全更新",
            severity="medium",
            remediation="安装并启用自动更新: sudo apt install unattended-upgrades && sudo dpkg-reconfigure -plow unattended-upgrades",
        )
        try:
            if os.path.exists("/etc/apt/apt.conf.d/20auto-upgrades"):
                with open("/etc/apt/apt.conf.d/20auto-upgrades", "r") as f:
                    content = f.read()
                if 'APT::Periodic::Update-Package-Lists "1"' in content:
                    check.status = "pass"
                    check.result_detail = "自动更新已配置"
                else:
                    check.status = "warning"
                    check.result_detail = "自动更新配置文件存在但未正确启用"
            elif os.path.exists("/etc/dnf/automatic.conf"):
                check.status = "pass"
                check.result_detail = "DNF自动更新已配置"
            else:
                check.status = "warning"
                check.result_detail = "未检测到自动更新配置"
        except Exception as e:
            check.status = "warning"
            check.result_detail = "检查失败: {}".format(str(e))
        check.checked_at = now
        checks.append(check)

        # 4. 内核版本检查
        check = ComplianceCheck(
            category="系统安全",
            name="内核版本检查",
            description="检查系统内核版本是否为较新版本",
            severity="medium",
            remediation="升级系统内核: sudo apt update && sudo apt upgrade linux-image-*",
        )
        try:
            result = subprocess.run(
                ["uname", "-r"], capture_output=True, text=True, timeout=10,
            )
            kernel_version = result.stdout.strip()
            # 提取主版本号
            version_match = re.search(r"(\d+)\.(\d+)", kernel_version)
            if version_match:
                major = int(version_match.group(1))
                minor = int(version_match.group(2))
                if major >= 5 or (major == 4 and minor >= 14):
                    check.status = "pass"
                    check.result_detail = "内核版本 {} 较新".format(kernel_version)
                else:
                    check.status = "warning"
                    check.result_detail = "内核版本 {} 偏旧，建议升级".format(kernel_version)
            else:
                check.status = "warning"
                check.result_detail = "无法解析内核版本: {}".format(kernel_version)
        except Exception as e:
            check.status = "warning"
            check.result_detail = "检查失败: {}".format(str(e))
        check.checked_at = now
        checks.append(check)

        # 5. SSH root登录禁用
        check = ComplianceCheck(
            category="系统安全",
            name="SSH root登录禁用",
            description="检查SSH是否禁止root直接登录",
            severity="high",
            remediation="编辑/etc/ssh/sshd_config，设置PermitRootLogin no，然后重启SSH服务",
        )
        try:
            sshd_config_paths = [
                "/etc/ssh/sshd_config",
                "/etc/ssh/sshd_config.d/00-compliance.conf",
            ]
            found_config = False
            for config_path in sshd_config_paths:
                if os.path.exists(config_path):
                    with open(config_path, "r") as f:
                        content = f.read()
                    found_config = True
                    # 检查是否有 PermitRootLogin no
                    for line in content.splitlines():
                        line = line.strip()
                        if line.startswith("#"):
                            continue
                        if "PermitRootLogin" in line:
                            if "no" in line.lower():
                                check.status = "pass"
                                check.result_detail = "SSH root登录已禁用"
                            else:
                                check.status = "fail"
                                check.result_detail = "SSH允许root登录: {}".format(line)
                            break
                    if check.status == "not_checked" and found_config:
                        check.status = "warning"
                        check.result_detail = "未显式配置PermitRootLogin，默认可能允许root登录"
                    if check.status != "not_checked":
                        break

            if not found_config:
                check.status = "warning"
                check.result_detail = "未找到SSH配置文件"
        except Exception as e:
            check.status = "warning"
            check.result_detail = "检查失败: {}".format(str(e))
        check.checked_at = now
        checks.append(check)

        # 6. SSH密码认证
        check = ComplianceCheck(
            category="系统安全",
            name="SSH密码认证",
            description="检查SSH是否禁用密码认证（建议使用密钥认证）",
            severity="medium",
            remediation="编辑/etc/ssh/sshd_config，设置PasswordAuthentication no，配置公钥认证",
        )
        try:
            sshd_config = "/etc/ssh/sshd_config"
            if os.path.exists(sshd_config):
                with open(sshd_config, "r") as f:
                    content = f.read()
                for line in content.splitlines():
                    line = line.strip()
                    if line.startswith("#"):
                        continue
                    if "PasswordAuthentication" in line:
                        if "no" in line.lower():
                            check.status = "pass"
                            check.result_detail = "SSH密码认证已禁用，使用密钥认证"
                        else:
                            check.status = "warning"
                            check.result_detail = "SSH仍允许密码认证，建议使用密钥认证"
                        break
                else:
                    check.status = "warning"
                    check.result_detail = "未显式配置PasswordAuthentication"
            else:
                check.status = "warning"
                check.result_detail = "未找到SSH配置文件"
        except Exception as e:
            check.status = "warning"
            check.result_detail = "检查失败: {}".format(str(e))
        check.checked_at = now
        checks.append(check)

        # 7. 密码策略检查
        check = ComplianceCheck(
            category="系统安全",
            name="密码策略检查",
            description="检查密码最小长度和复杂度要求",
            severity="high",
            remediation="安装libpam-pwquality并配置/etc/security/pwquality.conf: minlen=12, minclass=3",
        )
        try:
            pwquality_path = "/etc/security/pwquality.conf"
            login_defs_path = "/etc/login.defs"
            min_len = 0
            has_complexity = False

            if os.path.exists(pwquality_path):
                with open(pwquality_path, "r") as f:
                    content = f.read()
                for line in content.splitlines():
                    line = line.strip()
                    if line.startswith("#") or not line:
                        continue
                    if "minlen" in line:
                        parts = line.split("=")
                        if len(parts) >= 2:
                            min_len = int(parts[1].strip())
                    if "minclass" in line or "dcredit" in line or "ucredit" in line:
                        has_complexity = True

            if os.path.exists(login_defs_path):
                with open(login_defs_path, "r") as f:
                    content = f.read()
                for line in content.splitlines():
                    line = line.strip()
                    if line.startswith("#") or not line:
                        continue
                    if "PASS_MIN_LEN" in line:
                        parts = line.split()
                        if len(parts) >= 2:
                            val = int(parts[1])
                            if val > min_len:
                                min_len = val

            if min_len >= 12 and has_complexity:
                check.status = "pass"
                check.result_detail = "密码策略合规: 最小长度={}, 已配置复杂度要求".format(min_len)
            elif min_len >= 8:
                check.status = "warning"
                check.result_detail = "密码最小长度为{}，建议至少12位并启用复杂度要求".format(min_len)
            else:
                check.status = "fail"
                check.result_detail = "密码策略不足: 最小长度={}, 未配置复杂度要求".format(min_len)
        except Exception as e:
            check.status = "warning"
            check.result_detail = "检查失败: {}".format(str(e))
        check.checked_at = now
        checks.append(check)

        # 8. 空密码检查
        check = ComplianceCheck(
            category="系统安全",
            name="空密码用户检查",
            description="检查系统中是否存在空密码用户",
            severity="critical",
            remediation="为所有用户设置强密码: passwd <username>，或锁定空密码账户: passwd -l <username>",
        )
        try:
            result = subprocess.run(
                ["awk", "-F:", '($2 == "" || $2 == "!") {print $1}',
                 "/etc/shadow"],
                capture_output=True, text=True, timeout=10,
            )
            empty_users = [u for u in result.stdout.strip().splitlines() if u]
            if not empty_users:
                check.status = "pass"
                check.result_detail = "未发现空密码用户"
            else:
                check.status = "fail"
                check.result_detail = "发现空密码用户: {}".format(", ".join(empty_users))
        except Exception as e:
            check.status = "warning"
            check.result_detail = "检查失败: {}".format(str(e))
        check.checked_at = now
        checks.append(check)

        # 9. SUID文件检查
        check = ComplianceCheck(
            category="系统安全",
            name="SUID文件检查",
            description="检查系统中异常的SUID/SGID文件",
            severity="high",
            remediation="审查并移除不必要的SUID位: sudo chmod u-s <file>，仅保留必要的SUID文件",
        )
        try:
            result = subprocess.run(
                ["find", "/", "-perm", "-4000", "-type", "f", "-exec",
                 "ls", "-la", "{}", ";"],
                capture_output=True, text=True, timeout=30,
            )
            suid_files = [
                line.strip() for line in result.stdout.strip().splitlines() if line.strip()
            ]
            # 已知安全的SUID文件
            safe_suid = [
                "/usr/bin/sudo", "/usr/bin/passwd", "/usr/bin/su",
                "/usr/bin/newgrp", "/usr/bin/gpasswd", "/usr/bin/chsh",
                "/usr/bin/chfn", "/usr/bin/mount", "/usr/bin/umount",
                "/usr/bin/pkexec", "/usr/lib/openssh/ssh-keysign",
                "/usr/lib/dbus-1.0/dbus-daemon-launch-helper",
            ]
            unsafe_files = [
                f for f in suid_files
                if not any(safe in f for safe in safe_suid)
            ]
            if not unsafe_files:
                check.status = "pass"
                check.result_detail = "SUID文件检查通过，共{}个已知安全SUID文件".format(len(suid_files))
            else:
                check.status = "warning"
                check.result_detail = "发现{}个可能异常的SUID文件，需人工审查".format(len(unsafe_files))
        except Exception as e:
            check.status = "warning"
            check.result_detail = "检查失败: {}".format(str(e))
        check.checked_at = now
        checks.append(check)

        # 10. 定时任务检查
        check = ComplianceCheck(
            category="系统安全",
            name="定时任务检查",
            description="检查系统定时任务中是否有可疑条目",
            severity="medium",
            remediation="审查并移除可疑的定时任务: crontab -e 或检查/etc/cron.*目录",
        )
        try:
            suspicious_patterns = [
                r"wget\s+", r"curl\s+", r"/dev/tcp/", r"nc\s+",
                r"bash\s+-i", r"python\s+-c", r"perl\s+-e",
                r"base64\s+-d", r"\|.*sh\b",
            ]
            suspicious_crons = []
            cron_dirs = [
                "/etc/crontab", "/etc/cron.d/", "/var/spool/cron/crontabs/",
            ]
            for cron_path in cron_dirs:
                if os.path.isfile(cron_path):
                    with open(cron_path, "r") as f:
                        for i, line in enumerate(f.readlines(), 1):
                            line = line.strip()
                            if line.startswith("#") or not line:
                                continue
                            for pattern in suspicious_patterns:
                                if re.search(pattern, line):
                                    suspicious_crons.append(
                                        "{}:{}: {}".format(cron_path, i, line)
                                    )
                                    break
                elif os.path.isdir(cron_path):
                    for fname in os.listdir(cron_path):
                        fpath = os.path.join(cron_path, fname)
                        if os.path.isfile(fpath):
                            try:
                                with open(fpath, "r") as f:
                                    for i, line in enumerate(f.readlines(), 1):
                                        line = line.strip()
                                        if line.startswith("#") or not line:
                                            continue
                                        for pattern in suspicious_patterns:
                                            if re.search(pattern, line):
                                                suspicious_crons.append(
                                                    "{}:{}: {}".format(fpath, i, line)
                                                )
                                                break
                            except Exception:
                                pass

            if not suspicious_crons:
                check.status = "pass"
                check.result_detail = "定时任务检查通过，未发现可疑条目"
            else:
                check.status = "fail"
                check.result_detail = "发现{}个可疑定时任务".format(len(suspicious_crons))
        except Exception as e:
            check.status = "warning"
            check.result_detail = "检查失败: {}".format(str(e))
        check.checked_at = now
        checks.append(check)

        return checks

    # ---- 网络安全检查 ----

    def _check_network_security(self, standard: str) -> List[ComplianceCheck]:
        """网络安全检查（5项）"""
        checks = []
        now = datetime.now()

        # 1. 开放端口检查
        check = ComplianceCheck(
            category="网络安全",
            name="开放端口检查",
            description="检查系统监听的网络端口",
            severity="high",
            remediation="关闭不必要的网络服务: sudo systemctl disable <service>，或使用防火墙限制端口访问",
        )
        try:
            result = subprocess.run(
                ["ss", "-tlnp"], capture_output=True, text=True, timeout=10,
            )
            lines = result.stdout.strip().splitlines()
            # 跳过标题行
            listening_ports = []
            for line in lines[1:]:
                parts = line.split()
                if len(parts) >= 4:
                    listening_ports.append(parts[3])

            # 高危端口
            dangerous_ports = [23, 21, 445, 3389, 5900, 512, 513, 514]
            found_dangerous = []
            for port_str in listening_ports:
                for dp in dangerous_ports:
                    if ":{} ".format(dp) in port_str or ":{}$".format(dp) in port_str:
                        found_dangerous.append("{} ({})".format(dp, port_str))

            if not found_dangerous:
                check.status = "pass"
                check.result_detail = "未发现高危端口开放，共{}个监听端口".format(len(listening_ports))
            else:
                check.status = "fail"
                check.result_detail = "发现高危端口: {}".format(", ".join(found_dangerous))
        except Exception as e:
            check.status = "warning"
            check.result_detail = "检查失败: {}".format(str(e))
        check.checked_at = now
        checks.append(check)

        # 2. 网络监听服务
        check = ComplianceCheck(
            category="网络安全",
            name="网络监听服务",
            description="检查对外监听的网络服务数量",
            severity="medium",
            remediation="禁用不必要的外部监听服务，仅保留必需的网络服务",
        )
        try:
            result = subprocess.run(
                ["ss", "-tlnp"], capture_output=True, text=True, timeout=10,
            )
            lines = result.stdout.strip().splitlines()
            service_count = max(0, len(lines) - 1)

            if service_count <= 5:
                check.status = "pass"
                check.result_detail = "监听服务数量合理: {}个".format(service_count)
            elif service_count <= 10:
                check.status = "warning"
                check.result_detail = "监听服务较多: {}个，建议审查是否全部必要".format(service_count)
            else:
                check.status = "fail"
                check.result_detail = "监听服务过多: {}个，存在安全风险".format(service_count)
        except Exception as e:
            check.status = "warning"
            check.result_detail = "检查失败: {}".format(str(e))
        check.checked_at = now
        checks.append(check)

        # 3. IP转发状态
        check = ComplianceCheck(
            category="网络安全",
            name="IP转发状态",
            description="检查IP转发是否启用（非网关设备应禁用）",
            severity="medium",
            remediation="如非网关设备，禁用IP转发: echo 0 > /proc/sys/net/ipv4/ip_forward",
        )
        try:
            ip_forward_path = "/proc/sys/net/ipv4/ip_forward"
            if os.path.exists(ip_forward_path):
                with open(ip_forward_path, "r") as f:
                    value = f.read().strip()
                if value == "0":
                    check.status = "pass"
                    check.result_detail = "IP转发已禁用"
                else:
                    check.status = "warning"
                    check.result_detail = "IP转发已启用，如非网关设备建议禁用"
            else:
                check.status = "warning"
                check.result_detail = "无法读取IP转发状态"
        except Exception as e:
            check.status = "warning"
            check.result_detail = "检查失败: {}".format(str(e))
        check.checked_at = now
        checks.append(check)

        # 4. ICMP重定向
        check = ComplianceCheck(
            category="网络安全",
            name="ICMP重定向",
            description="检查是否接受ICMP重定向（应禁用以防中间人攻击）",
            severity="medium",
            remediation="禁用ICMP重定向: echo 0 > /proc/sys/net/ipv4/conf/all/accept_redirects",
        )
        try:
            redirect_path = "/proc/sys/net/ipv4/conf/all/accept_redirects"
            if os.path.exists(redirect_path):
                with open(redirect_path, "r") as f:
                    value = f.read().strip()
                if value == "0":
                    check.status = "pass"
                    check.result_detail = "ICMP重定向已禁用"
                else:
                    check.status = "fail"
                    check.result_detail = "ICMP重定向已启用，存在中间人攻击风险"
            else:
                check.status = "warning"
                check.result_detail = "无法读取ICMP重定向状态"
        except Exception as e:
            check.status = "warning"
            check.result_detail = "检查失败: {}".format(str(e))
        check.checked_at = now
        checks.append(check)

        # 5. 源路由
        check = ComplianceCheck(
            category="网络安全",
            name="源路由检查",
            description="检查是否接受源路由包（应禁用）",
            severity="medium",
            remediation="禁用源路由: echo 0 > /proc/sys/net/ipv4/conf/all/accept_source_route",
        )
        try:
            src_route_path = "/proc/sys/net/ipv4/conf/all/accept_source_route"
            if os.path.exists(src_route_path):
                with open(src_route_path, "r") as f:
                    value = f.read().strip()
                if value == "0":
                    check.status = "pass"
                    check.result_detail = "源路由已禁用"
                else:
                    check.status = "fail"
                    check.result_detail = "源路由已启用，存在IP欺骗风险"
            else:
                check.status = "warning"
                check.result_detail = "无法读取源路由状态"
        except Exception as e:
            check.status = "warning"
            check.result_detail = "检查失败: {}".format(str(e))
        check.checked_at = now
        checks.append(check)

        return checks

    # ---- 用户管理检查 ----

    def _check_user_management(self, standard: str) -> List[ComplianceCheck]:
        """用户管理检查（5项）"""
        checks = []
        now = datetime.now()

        # 1. 空密码用户
        check = ComplianceCheck(
            category="用户管理",
            name="空密码用户检查",
            description="检查/etc/shadow中是否存在空密码账户",
            severity="critical",
            remediation="为空密码用户设置密码或锁定账户: passwd -l <username>",
        )
        try:
            result = subprocess.run(
                ["awk", "-F:", '($2 == "") {print $1}', "/etc/shadow"],
                capture_output=True, text=True, timeout=10,
            )
            empty_users = [u for u in result.stdout.strip().splitlines() if u]
            if not empty_users:
                check.status = "pass"
                check.result_detail = "无空密码用户"
            else:
                check.status = "fail"
                check.result_detail = "空密码用户: {}".format(", ".join(empty_users))
        except Exception as e:
            check.status = "warning"
            check.result_detail = "检查失败: {}".format(str(e))
        check.checked_at = now
        checks.append(check)

        # 2. UID=0非root用户
        check = ComplianceCheck(
            category="用户管理",
            name="UID=0非root用户",
            description="检查是否存在UID为0的非root用户",
            severity="critical",
            remediation="修改非root用户的UID: usermod -u <new_uid> <username>",
        )
        try:
            result = subprocess.run(
                ["awk", "-F:", '($3 == 0 && $1 != "root") {print $1}',
                 "/etc/passwd"],
                capture_output=True, text=True, timeout=10,
            )
            uid0_users = [u for u in result.stdout.strip().splitlines() if u]
            if not uid0_users:
                check.status = "pass"
                check.result_detail = "仅root用户UID为0"
            else:
                check.status = "fail"
                check.result_detail = "UID=0的非root用户: {}".format(", ".join(uid0_users))
        except Exception as e:
            check.status = "warning"
            check.result_detail = "检查失败: {}".format(str(e))
        check.checked_at = now
        checks.append(check)

        # 3. 可登录用户数
        check = ComplianceCheck(
            category="用户管理",
            name="可登录用户数",
            description="检查系统中具有登录权限的用户数量",
            severity="low",
            remediation="审查并移除不必要的可登录用户，或将其shell改为/usr/sbin/nologin",
        )
        try:
            result = subprocess.run(
                ["awk", "-F:", '($7 !~ /(nologin|false|sync|halt|shutdown)/) {print $1}',
                 "/etc/passwd"],
                capture_output=True, text=True, timeout=10,
            )
            login_users = [u for u in result.stdout.strip().splitlines() if u]
            # 排除系统服务用户
            system_users = {
                "root", "daemon", "bin", "sys", "sync", "games", "man",
                "lp", "mail", "news", "uucp", "proxy", "www-data",
                "backup", "list", "irc", "gnats", "nobody", "systemd-network",
                "systemd-resolve", "systemd-timesync", "messagebus", "avahi",
                "sshd", "polkitd", "rtkit", "pulse",
            }
            real_users = [u for u in login_users if u not in system_users]

            if len(real_users) <= 5:
                check.status = "pass"
                check.result_detail = "可登录用户数: {}".format(len(real_users))
            elif len(real_users) <= 10:
                check.status = "warning"
                check.result_detail = "可登录用户较多: {}个，建议审查".format(len(real_users))
            else:
                check.status = "fail"
                check.result_detail = "可登录用户过多: {}个".format(len(real_users))
        except Exception as e:
            check.status = "warning"
            check.result_detail = "检查失败: {}".format(str(e))
        check.checked_at = now
        checks.append(check)

        # 4. 过期账户
        check = ComplianceCheck(
            category="用户管理",
            name="过期账户检查",
            description="检查是否存在已过期但仍活跃的用户账户",
            severity="medium",
            remediation="锁定或删除过期账户: passwd -l <username> 或 userdel <username>",
        )
        try:
            result = subprocess.run(
                ["awk", "-F:", '($7 !~ /(nologin|false)/) {print $1":"$8}',
                 "/etc/passwd"],
                capture_output=True, text=True, timeout=10,
            )
            expired_users = []
            for line in result.stdout.strip().splitlines():
                if ":" not in line:
                    continue
                parts = line.rsplit(":", 1)
                if len(parts) == 2:
                    username = parts[0]
                    expire_str = parts[1].strip()
                    if expire_str and expire_str != "0" and expire_str != "":
                        try:
                            expire_date = datetime.strptime(
                                expire_str, "%Y-%m-%d"
                            ) if "-" in expire_str else datetime.fromtimestamp(
                                int(expire_str)
                            )
                            if expire_date < now:
                                expired_users.append(username)
                        except (ValueError, OSError):
                            pass

            if not expired_users:
                check.status = "pass"
                check.result_detail = "未发现过期账户"
            else:
                check.status = "warning"
                check.result_detail = "发现过期账户: {}".format(", ".join(expired_users))
        except Exception as e:
            check.status = "warning"
            check.result_detail = "检查失败: {}".format(str(e))
        check.checked_at = now
        checks.append(check)

        # 5. 密码过期策略
        check = ComplianceCheck(
            category="用户管理",
            name="密码过期策略",
            description="检查用户密码最大有效期配置",
            severity="medium",
            remediation="设置密码最大有效期: chage -M 90 <username>，编辑/etc/login.defs设置PASS_MAX_DAYS",
        )
        try:
            login_defs = "/etc/login.defs"
            max_days = 0
            if os.path.exists(login_defs):
                with open(login_defs, "r") as f:
                    for line in f:
                        line = line.strip()
                        if line.startswith("PASS_MAX_DAYS"):
                            parts = line.split()
                            if len(parts) >= 2:
                                max_days = int(parts[1])
                                break

            if 1 <= max_days <= 90:
                check.status = "pass"
                check.result_detail = "密码最大有效期: {}天".format(max_days)
            elif max_days > 90:
                check.status = "warning"
                check.result_detail = "密码最大有效期过长: {}天，建议不超过90天".format(max_days)
            elif max_days == 99999:
                check.status = "fail"
                check.result_detail = "密码永不过期，存在安全风险"
            else:
                check.status = "warning"
                check.result_detail = "未配置密码过期策略"
        except Exception as e:
            check.status = "warning"
            check.result_detail = "检查失败: {}".format(str(e))
        check.checked_at = now
        checks.append(check)

        return checks

    # ---- 日志审计检查 ----

    def _check_log_audit(self, standard: str) -> List[ComplianceCheck]:
        """日志审计检查（4项）"""
        checks = []
        now = datetime.now()

        # 1. syslog/rsyslog状态
        check = ComplianceCheck(
            category="日志审计",
            name="syslog/rsyslog状态",
            description="检查系统日志服务是否运行",
            severity="high",
            remediation="启动日志服务: sudo systemctl enable --now rsyslog",
        )
        try:
            result = subprocess.run(
                ["systemctl", "is-active", "rsyslog"],
                capture_output=True, text=True, timeout=10,
            )
            if "active" in result.stdout.strip():
                check.status = "pass"
                check.result_detail = "rsyslog服务运行中"
            else:
                # 检查 syslog
                result2 = subprocess.run(
                    ["systemctl", "is-active", "syslog"],
                    capture_output=True, text=True, timeout=10,
                )
                if "active" in result2.stdout.strip():
                    check.status = "pass"
                    check.result_detail = "syslog服务运行中"
                else:
                    check.status = "fail"
                    check.result_detail = "日志服务未运行"
        except Exception as e:
            check.status = "warning"
            check.result_detail = "检查失败: {}".format(str(e))
        check.checked_at = now
        checks.append(check)

        # 2. 日志文件大小
        check = ComplianceCheck(
            category="日志审计",
            name="日志文件大小",
            description="检查系统日志文件大小是否合理（过大可能未配置轮转）",
            severity="low",
            remediation="配置logrotate: 编辑/etc/logrotate.d/下的配置文件",
        )
        try:
            log_dirs = ["/var/log/syslog", "/var/log/messages",
                        "/var/log/auth.log", "/var/log/kern.log"]
            total_size = 0
            large_logs = []
            for log_file in log_dirs:
                if os.path.exists(log_file):
                    size = os.path.getsize(log_file)
                    total_size += size
                    size_mb = size / (1024 * 1024)
                    if size_mb > 100:
                        large_logs.append("{} ({:.1f}MB)".format(log_file, size_mb))

            if not large_logs:
                check.status = "pass"
                check.result_detail = "日志文件大小正常，总计 {:.1f}MB".format(
                    total_size / (1024 * 1024)
                )
            else:
                check.status = "warning"
                check.result_detail = "以下日志文件过大: {}".format(", ".join(large_logs))
        except Exception as e:
            check.status = "warning"
            check.result_detail = "检查失败: {}".format(str(e))
        check.checked_at = now
        checks.append(check)

        # 3. 审计服务状态
        check = ComplianceCheck(
            category="日志审计",
            name="审计服务状态",
            description="检查auditd审计服务是否运行",
            severity="high",
            remediation="安装并启动auditd: sudo apt install auditd && sudo systemctl enable --now auditd",
        )
        try:
            result = subprocess.run(
                ["systemctl", "is-active", "auditd"],
                capture_output=True, text=True, timeout=10,
            )
            if "active" in result.stdout.strip():
                check.status = "pass"
                check.result_detail = "auditd审计服务运行中"
            else:
                check.status = "fail"
                check.result_detail = "auditd审计服务未运行"
        except Exception as e:
            check.status = "warning"
            check.result_detail = "检查失败: {}".format(str(e))
        check.checked_at = now
        checks.append(check)

        # 4. 登录超时配置
        check = ComplianceCheck(
            category="日志审计",
            name="登录超时配置",
            description="检查Shell空闲超时是否配置",
            severity="medium",
            remediation="在/etc/profile中添加: export TMOUT=300（5分钟超时）",
        )
        try:
            tmout_found = False
            tmout_value = 0
            profile_files = [
                "/etc/profile", "/etc/profile.d/*.sh",
                "/etc/bash.bashrc",
            ]
            for pattern in profile_files:
                import glob as glob_mod
                for fpath in glob_mod.glob(pattern):
                    try:
                        with open(fpath, "r") as f:
                            for line in f:
                                line = line.strip()
                                if line.startswith("#") or not line:
                                    continue
                                if "TMOUT" in line and "=" in line:
                                    tmout_found = True
                                    parts = line.split("=")
                                    if len(parts) >= 2:
                                        try:
                                            tmout_value = int(
                                                parts[1].strip().rstrip(";")
                                            )
                                        except ValueError:
                                            pass
                    except Exception:
                        pass

            if tmout_found and 60 <= tmout_value <= 600:
                check.status = "pass"
                check.result_detail = "登录超时已配置: {}秒".format(tmout_value)
            elif tmout_found and tmout_value > 600:
                check.status = "warning"
                check.result_detail = "登录超时过长: {}秒，建议不超过600秒".format(tmout_value)
            elif tmout_found:
                check.status = "warning"
                check.result_detail = "登录超时值异常: {}秒".format(tmout_value)
            else:
                check.status = "fail"
                check.result_detail = "未配置登录超时（TMOUT）"
        except Exception as e:
            check.status = "warning"
            check.result_detail = "检查失败: {}".format(str(e))
        check.checked_at = now
        checks.append(check)

        return checks

    # ---- 数据保护检查 ----

    def _check_data_protection(self, standard: str) -> List[ComplianceCheck]:
        """数据保护检查（3项）"""
        checks = []
        now = datetime.now()

        # 1. /tmp权限
        check = ComplianceCheck(
            category="数据保护",
            name="/tmp目录权限",
            description="检查/tmp目录权限设置（应设置sticky bit）",
            severity="medium",
            remediation="设置/tmp目录sticky bit: chmod +t /tmp",
        )
        try:
            stat_info = os.stat("/tmp")
            mode = oct(stat_info.st_mode)[-3:]
            has_sticky = bool(stat_info.st_mode & 0o1000)

            if has_sticky:
                check.status = "pass"
                check.result_detail = "/tmp权限: {}，已设置sticky bit".format(mode)
            else:
                check.status = "fail"
                check.result_detail = "/tmp权限: {}，未设置sticky bit".format(mode)
        except Exception as e:
            check.status = "warning"
            check.result_detail = "检查失败: {}".format(str(e))
        check.checked_at = now
        checks.append(check)

        # 2. 核心文件转储
        check = ComplianceCheck(
            category="数据保护",
            name="核心文件转储",
            description="检查是否禁用核心文件转储（防止敏感信息泄露）",
            severity="medium",
            remediation="禁用核心转储: echo '* hard core 0' >> /etc/security/limits.conf",
        )
        try:
            core_path = "/proc/sys/kernel/core_pattern"
            limits_path = "/etc/security/limits.conf"
            core_disabled = False

            if os.path.exists(core_path):
                with open(core_path, "r") as f:
                    pattern = f.read().strip()
                if pattern.startswith("|") or pattern == "/dev/null":
                    core_disabled = True
                    check.result_detail = "核心转储已重定向到: {}".format(pattern)

            if not core_disabled and os.path.exists(limits_path):
                with open(limits_path, "r") as f:
                    content = f.read()
                if "hard core 0" in content or "core 0" in content:
                    core_disabled = True
                    check.result_detail = "核心转储已在limits.conf中禁用"

            if core_disabled:
                check.status = "pass"
                if not check.result_detail:
                    check.result_detail = "核心文件转储已禁用"
            else:
                check.status = "warning"
                check.result_detail = "核心文件转储可能未禁用"
        except Exception as e:
            check.status = "warning"
            check.result_detail = "检查失败: {}".format(str(e))
        check.checked_at = now
        checks.append(check)

        # 3. 文件系统挂载选项
        check = ComplianceCheck(
            category="数据保护",
            name="文件系统挂载选项",
            description="检查关键文件系统是否使用了安全挂载选项",
            severity="medium",
            remediation="编辑/etc/fstab，为关键分区添加nodev,nosuid,noexec选项",
        )
        try:
            fstab_path = "/etc/fstab"
            if os.path.exists(fstab_path):
                with open(fstab_path, "r") as f:
                    lines = f.readlines()

                issues = []
                for line in lines:
                    line = line.strip()
                    if line.startswith("#") or not line:
                        continue
                    parts = line.split()
                    if len(parts) >= 4:
                        mount_point = parts[1]
                        options = parts[3]
                        # 检查/tmp
                        if mount_point == "/tmp":
                            if "nosuid" not in options:
                                issues.append("/tmp缺少nosuid选项")
                        # 检查/var/tmp
                        if mount_point == "/var/tmp":
                            if "nosuid" not in options:
                                issues.append("/var/tmp缺少nosuid选项")
                        # 检查/home
                        if mount_point == "/home":
                            if "nosuid" not in options:
                                issues.append("/home缺少nosuid选项")

                if not issues:
                    check.status = "pass"
                    check.result_detail = "文件系统挂载选项检查通过"
                else:
                    check.status = "warning"
                    check.result_detail = "; ".join(issues)
            else:
                check.status = "warning"
                check.result_detail = "未找到/etc/fstab"
        except Exception as e:
            check.status = "warning"
            check.result_detail = "检查失败: {}".format(str(e))
        check.checked_at = now
        checks.append(check)

        return checks

    # ---- 服务安全检查 ----

    def _check_service_security(self, standard: str) -> List[ComplianceCheck]:
        """服务安全检查（4项）"""
        checks = []
        now = datetime.now()

        # 1. 不必要服务检查
        check = ComplianceCheck(
            category="服务安全",
            name="不必要服务检查",
            description="检查是否存在不必要的高风险网络服务",
            severity="high",
            remediation="禁用不必要的服务: sudo systemctl disable --now <service>",
        )
        try:
            unnecessary_services = [
                "telnet", "rsh", "rlogin", "ftp", "tftp",
                "xinetd", "inetd", "chargen", "daytime", "echo",
                "finger",
            ]
            running_unnecessary = []
            for svc in unnecessary_services:
                result = subprocess.run(
                    ["systemctl", "is-active", svc],
                    capture_output=True, text=True, timeout=5,
                )
                if "active" in result.stdout.strip():
                    running_unnecessary.append(svc)

            if not running_unnecessary:
                check.status = "pass"
                check.result_detail = "未发现不必要的高风险服务"
            else:
                check.status = "fail"
                check.result_detail = "运行中的高风险服务: {}".format(
                    ", ".join(running_unnecessary)
                )
        except Exception as e:
            check.status = "warning"
            check.result_detail = "检查失败: {}".format(str(e))
        check.checked_at = now
        checks.append(check)

        # 2. SNMP配置
        check = ComplianceCheck(
            category="服务安全",
            name="SNMP配置检查",
            description="检查SNMP服务是否使用了默认社区字符串",
            severity="high",
            remediation="修改SNMP社区字符串为强密码，使用SNMPv3并启用认证加密",
        )
        try:
            result = subprocess.run(
                ["systemctl", "is-active", "snmpd"],
                capture_output=True, text=True, timeout=5,
            )
            if "active" not in result.stdout.strip():
                check.status = "pass"
                check.result_detail = "SNMP服务未运行"
            else:
                # 检查SNMP配置
                snmp_conf = "/etc/snmp/snmpd.conf"
                default_communities = ["public", "private"]
                found_defaults = []
                if os.path.exists(snmp_conf):
                    with open(snmp_conf, "r") as f:
                        content = f.read()
                    for community in default_communities:
                        # 简单检查，不区分大小写
                        if community.lower() in content.lower():
                            found_defaults.append(community)

                if found_defaults:
                    check.status = "fail"
                    check.result_detail = "SNMP使用默认社区字符串: {}".format(
                        ", ".join(found_defaults)
                    )
                else:
                    check.status = "warning"
                    check.result_detail = "SNMP服务运行中，请确认使用了安全配置"
        except Exception as e:
            check.status = "warning"
            check.result_detail = "检查失败: {}".format(str(e))
        check.checked_at = now
        checks.append(check)

        # 3. NTP配置
        check = ComplianceCheck(
            category="服务安全",
            name="NTP配置检查",
            description="检查NTP时间同步服务是否配置",
            severity="low",
            remediation="安装并配置NTP: sudo apt install ntp 或 chrony，配置可信时间服务器",
        )
        try:
            ntp_services = ["ntp", "chronyd", "systemd-timesyncd"]
            ntp_active = False
            active_service = ""
            for svc in ntp_services:
                result = subprocess.run(
                    ["systemctl", "is-active", svc],
                    capture_output=True, text=True, timeout=5,
                )
                if "active" in result.stdout.strip():
                    ntp_active = True
                    active_service = svc
                    break

            if ntp_active:
                check.status = "pass"
                check.result_detail = "时间同步服务运行中: {}".format(active_service)
            else:
                check.status = "warning"
                check.result_detail = "未检测到NTP时间同步服务"
        except Exception as e:
            check.status = "warning"
            check.result_detail = "检查失败: {}".format(str(e))
        check.checked_at = now
        checks.append(check)

        # 4. DNS配置
        check = ComplianceCheck(
            category="服务安全",
            name="DNS配置检查",
            description="检查系统DNS配置是否合理",
            severity="low",
            remediation="配置可信DNS服务器，避免使用不可信的公共DNS",
        )
        try:
            resolv_path = "/etc/resolv.conf"
            if os.path.exists(resolv_path):
                with open(resolv_path, "r") as f:
                    content = f.read()
                nameservers = re.findall(
                    r"nameserver\s+([\d.]+)", content
                )
                if nameservers:
                    check.status = "pass"
                    check.result_detail = "已配置DNS服务器: {}".format(
                        ", ".join(nameservers)
                    )
                else:
                    check.status = "warning"
                    check.result_detail = "未配置DNS服务器"
            else:
                check.status = "warning"
                check.result_detail = "未找到DNS配置文件"
        except Exception as e:
            check.status = "warning"
            check.result_detail = "检查失败: {}".format(str(e))
        check.checked_at = now
        checks.append(check)

        return checks

    # ---- 网络设备检查 ----

    def _check_network_device(self, device: dict) -> List[ComplianceCheck]:
        """
        检查单个网络设备的配置合规性
        通过SSH连接设备，采集配置并分析

        Args:
            device: 设备信息 {host, username, password, vendor, port}
        """
        checks = []
        now = datetime.now().isoformat()
        vendor = device.get("vendor", "cisco")
        host = device.get("host", "")

        # 1. SSH连接并采集配置
        config_text = self._ssh_collect_config(device)
        if config_text is None:
            check = ComplianceCheck(
                category="网络设备",
                name=f"设备连接 ({host})",
                description="SSH连接设备并采集运行配置",
                severity="critical",
                status="fail",
                result_detail=f"无法连接到设备 {host}，请检查SSH配置和凭据",
                remediation="确认设备已启用SSH服务，检查用户名密码是否正确",
            )
            check.checked_at = now
            checks.append(check)
            return checks

        config_lower = config_text.lower()

        # 2. 检查密码策略
        check = ComplianceCheck(
            category="网络设备",
            name="密码复杂度策略",
            description="检查设备是否配置了密码复杂度要求",
            severity="high",
            remediation="配置密码最小长度>=8，要求包含大小写字母、数字和特殊字符",
        )
        try:
            if vendor == "cisco":
                if "secret" in config_lower or "password" in config_lower:
                    if any(kw in config_lower for kw in ["min-length", "complexity", "strength"]):
                        check.status = "pass"
                        check.result_detail = "已配置密码复杂度策略"
                    else:
                        check.status = "warning"
                        check.result_detail = "检测到密码配置但未发现复杂度策略"
                else:
                    check.status = "fail"
                    check.result_detail = "未检测到密码配置"
            elif vendor in ("huawei", "h3c"):
                if any(kw in config_lower for kw in ["password-policy", "pw-policy", "密码策略"]):
                    check.status = "pass"
                    check.result_detail = "已配置密码策略"
                else:
                    check.status = "warning"
                    check.result_detail = "未发现密码策略配置"
            else:
                check.status = "warning"
                check.result_detail = "未知厂商，无法自动检测"
        except Exception as e:
            check.status = "warning"
            check.result_detail = "检查失败: {}".format(str(e))
        check.checked_at = now
        checks.append(check)

        # 3. 检查SSH安全配置
        check = ComplianceCheck(
            category="网络设备",
            name="SSH安全配置",
            description="检查SSH版本和加密算法配置",
            severity="high",
            remediation="使用SSH v2，禁用弱加密算法，配置登录超时",
        )
        try:
            if "ssh" in config_lower:
                if "ssh version 2" in config_lower or "ssh v2" in config_lower:
                    check.status = "pass"
                    check.result_detail = "已启用SSH v2"
                else:
                    check.status = "warning"
                    check.result_detail = "SSH版本未明确指定，建议确认使用v2"

                if any(kw in config_lower for kw in ["des", "3des", "rc4", "md5"]):
                    check.status = "warning"
                    check.result_detail = "检测到弱加密算法，建议禁用DES/3DES/RC4/MD5"
            else:
                check.status = "warning"
                check.result_detail = "未检测到SSH配置"
        except Exception as e:
            check.status = "warning"
            check.result_detail = "检查失败: {}".format(str(e))
        check.checked_at = now
        checks.append(check)

        # 4. 检查Telnet
        check = ComplianceCheck(
            category="网络设备",
            name="Telnet服务检查",
            description="检查是否启用了不安全的Telnet服务",
            severity="high",
            remediation="禁用Telnet，仅使用SSH进行远程管理",
        )
        try:
            if "telnet" in config_lower:
                if any(kw in config_lower for kw in ["no telnet", "transport input ssh"]):
                    check.status = "pass"
                    check.result_detail = "Telnet已禁用或已限制仅SSH访问"
                else:
                    check.status = "fail"
                    check.result_detail = "检测到Telnet服务启用，建议禁用"
            else:
                check.status = "pass"
                check.result_detail = "未检测到Telnet配置"
        except Exception as e:
            check.status = "warning"
            check.result_detail = "检查失败: {}".format(str(e))
        check.checked_at = now
        checks.append(check)

        # 5. 检查SNMP
        check = ComplianceCheck(
            category="网络设备",
            name="SNMP安全配置",
            description="检查SNMP版本和Community字符串",
            severity="medium",
            remediation="使用SNMPv3，修改默认community字符串",
        )
        try:
            if "snmp" in config_lower:
                if "snmp-server community" in config_lower:
                    if "public" in config_lower or "private" in config_lower:
                        check.status = "fail"
                        check.result_detail = "使用默认SNMP community字符串(public/private)"
                    else:
                        check.status = "warning"
                        check.result_detail = "已配置自定义community，建议使用SNMPv3"
                elif "snmp v3" in config_lower or "snmpv3" in config_lower:
                    check.status = "pass"
                    check.result_detail = "已配置SNMPv3"
                else:
                    check.status = "warning"
                    check.result_detail = "检测到SNMP配置，建议确认版本和认证"
            else:
                check.status = "pass"
                check.result_detail = "未检测到SNMP配置"
        except Exception as e:
            check.status = "warning"
            check.result_detail = "检查失败: {}".format(str(e))
        check.checked_at = now
        checks.append(check)

        # 6. 检查NTP
        check = ComplianceCheck(
            category="网络设备",
            name="NTP时间同步",
            description="检查设备是否配置了NTP时间同步",
            severity="low",
            remediation="配置NTP服务器，确保网络设备时间一致",
        )
        try:
            if "ntp" in config_lower or "clock timezone" in config_lower:
                check.status = "pass"
                check.result_detail = "已配置NTP时间同步"
            else:
                check.status = "warning"
                check.result_detail = "未检测到NTP配置"
        except Exception as e:
            check.status = "warning"
            check.result_detail = "检查失败: {}".format(str(e))
        check.checked_at = now
        checks.append(check)

        # 7. 检查日志
        check = ComplianceCheck(
            category="网络设备",
            name="日志服务器配置",
            description="检查设备是否配置了远程日志服务器",
            severity="medium",
            remediation="配置远程Syslog服务器，集中收集设备日志",
        )
        try:
            if any(kw in config_lower for kw in ["logging server", "syslog", "info-center"]):
                check.status = "pass"
                check.result_detail = "已配置远程日志服务器"
            else:
                check.status = "warning"
                check.result_detail = "未检测到远程日志服务器配置"
        except Exception as e:
            check.status = "warning"
            check.result_detail = "检查失败: {}".format(str(e))
        check.checked_at = now
        checks.append(check)

        # 8. 检查ACL/防火墙
        check = ComplianceCheck(
            category="网络设备",
            name="访问控制列表(ACL)",
            description="检查设备是否配置了基本ACL规则",
            severity="medium",
            remediation="配置ACL限制管理访问，遵循最小权限原则",
        )
        try:
            if any(kw in config_lower for kw in ["access-list", "acl", "traffic-filter", "packet-filter"]):
                check.status = "pass"
                check.result_detail = "已配置ACL规则"
            else:
                check.status = "warning"
                check.result_detail = "未检测到ACL配置，建议配置基本访问控制"
        except Exception as e:
            check.status = "warning"
            check.result_detail = "检查失败: {}".format(str(e))
        check.checked_at = now
        checks.append(check)

        # 9. 检查Banner
        check = ComplianceCheck(
            category="网络设备",
            name="登录Banner",
            description="检查是否配置了安全警告Banner",
            severity="low",
            remediation="配置登录Banner，包含法律免责声明，不暴露设备信息",
        )
        try:
            if any(kw in config_lower for kw in ["banner", "header", "legal"]):
                check.status = "pass"
                check.result_detail = "已配置登录Banner"
            else:
                check.status = "warning"
                check.result_detail = "未检测到Banner配置"
        except Exception as e:
            check.status = "warning"
            check.result_detail = "检查失败: {}".format(str(e))
        check.checked_at = now
        checks.append(check)

        # 10. 检查不必要服务
        check = ComplianceCheck(
            category="网络设备",
            name="不必要服务检查",
            description="检查是否启用了不必要的服务（CDP/HTTP/FTP等）",
            severity="medium",
            remediation="禁用CDP、HTTP Server、FTP等不必要的服务",
        )
        try:
            unnecessary = []
            if "cdp" in config_lower and "no cdp" not in config_lower:
                unnecessary.append("CDP")
            if "http server" in config_lower and "no ip http server" not in config_lower:
                unnecessary.append("HTTP Server")
            if "ip http secure-server" in config_lower:
                pass  # secure-server是安全的
            if "ftp-server" in config_lower:
                unnecessary.append("FTP Server")
            if "lldp" in config_lower and "no lldp" not in config_lower:
                unnecessary.append("LLDP")

            if unnecessary:
                check.status = "warning"
                check.result_detail = "检测到可能不必要的服务: {}".format(", ".join(unnecessary))
            else:
                check.status = "pass"
                check.result_detail = "未检测到明显不必要的服务"
        except Exception as e:
            check.status = "warning"
            check.result_detail = "检查失败: {}".format(str(e))
        check.checked_at = now
        checks.append(check)

        return checks

    def _ssh_collect_config(self, device: dict) -> Optional[str]:
        """通过SSH连接设备并采集运行配置"""
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(
                hostname=device.get("host"),
                port=device.get("port", 22),
                username=device.get("username"),
                password=device.get("password"),
                timeout=10,
                allow_agent=False,
                look_for_keys=False,
            )

            vendor = device.get("vendor", "cisco").lower()
            # 根据厂商选择命令
            if vendor == "cisco":
                cmd = "show running-config"
            elif vendor in ("huawei", "h3c"):
                cmd = "display current-configuration"
            elif vendor == "juniper":
                cmd = "show configuration | no-more"
            else:
                cmd = "show running-config"

            stdin, stdout, stderr = client.exec_command(cmd, timeout=30)
            config = stdout.read().decode("utf-8", errors="replace")
            client.close()
            return config if config.strip() else None

        except paramiko.AuthenticationException:
            logger.warning("SSH认证失败: {}".format(device.get("host")))
            return None
        except paramiko.SSHException as e:
            logger.warning("SSH连接失败: {} - {}".format(device.get("host"), e))
            return None
        except Exception as e:
            logger.warning("SSH采集配置失败: {} - {}".format(device.get("host"), e))
            return None

    def check_network_devices(self, devices: List[dict]) -> List[ComplianceCheck]:
        """
        检查多个网络设备的合规性

        Args:
            devices: 设备列表 [{host, username, password, vendor, port}]
        """
        all_checks = []
        for device in devices:
            device_checks = self._check_network_device(device)
            all_checks.extend(device_checks)
        return all_checks

    def test_device_connection(self, device: dict) -> dict:
        """测试设备SSH连接"""
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(
                hostname=device.get("host"),
                port=device.get("port", 22),
                username=device.get("username"),
                password=device.get("password"),
                timeout=10,
                allow_agent=False,
                look_for_keys=False,
            )
            client.close()
            return {"success": True, "message": "连接成功"}
        except paramiko.AuthenticationException:
            return {"success": False, "message": "认证失败，请检查用户名密码"}
        except paramiko.SSHException as e:
            return {"success": False, "message": "SSH连接失败: {}".format(str(e))}
        except Exception as e:
            return {"success": False, "message": "连接失败: {}".format(str(e))}

    # ---- 导出方法 ----

    def _export_json(self, report: ComplianceReport) -> str:
        """导出为JSON格式"""
        return json.dumps(report.to_dict(), ensure_ascii=False, indent=2)

    def _export_csv(self, report: ComplianceReport) -> str:
        """导出为CSV格式"""
        import io
        output = io.StringIO()
        # 报告头
        output.write("合规检查报告\n")
        output.write("标题,{}\n".format(report.title))
        output.write("标准,{}\n".format(report._get_standard_name()))
        output.write("分数,{}\n".format(report.score))
        output.write("总检查项,{}\n".format(report.total_checks))
        output.write("通过,{}\n".format(report.passed))
        output.write("失败,{}\n".format(report.failed))
        output.write("警告,{}\n".format(report.warnings))
        output.write("生成时间,{}\n".format(
            report.created_at.strftime("%Y-%m-%d %H:%M:%S")
        ))
        output.write("\n")

        # 检查项详情
        output.write(
            "分类,名称,描述,严重度,状态,详情,修复建议\n"
        )
        for check in report.checks:
            output.write(
                "{},{},{},{},{},{},{}\n".format(
                    check.category, check.name, check.description,
                    check.severity, check.status, check.result_detail,
                    check.remediation,
                )
            )

        return output.getvalue()

    def _export_html(self, report: ComplianceReport) -> str:
        """导出为HTML格式"""
        score_color = self._get_score_color(report.score)
        status_badge = {
            "pass": '<span style="color:#22c55e;">通过</span>',
            "fail": '<span style="color:#ef4444;">失败</span>',
            "warning": '<span style="color:#f59e0b;">警告</span>',
            "not_checked": '<span style="color:#94a3b8;">未检查</span>',
        }
        severity_badge = {
            "critical": '<span style="color:#ef4444;font-weight:bold;">严重</span>',
            "high": '<span style="color:#f97316;font-weight:bold;">高危</span>',
            "medium": '<span style="color:#eab308;">中危</span>',
            "low": '<span style="color:#22c55e;">低危</span>',
            "info": '<span style="color:#3b82f6;">信息</span>',
        }

        html = """<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<title>{title}</title>
<style>
body {{ font-family: -apple-system, sans-serif; margin: 40px; background: #0f172a; color: #e2e8f0; }}
.container {{ max-width: 1200px; margin: 0 auto; }}
h1 {{ color: #60a5fa; border-bottom: 2px solid #1e293b; padding-bottom: 10px; }}
.score {{ font-size: 64px; font-weight: bold; color: {score_color}; text-align: center; margin: 20px 0; }}
.stats {{ display: flex; gap: 20px; justify-content: center; margin: 20px 0; }}
.stat {{ background: #1e293b; padding: 15px 25px; border-radius: 8px; text-align: center; }}
.stat .num {{ font-size: 28px; font-weight: bold; }}
.stat .label {{ color: #94a3b8; font-size: 14px; }}
table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
th, td {{ padding: 10px; text-align: left; border-bottom: 1px solid #1e293b; font-size: 13px; }}
th {{ color: #94a3b8; background: #1e293b; }}
tr:hover {{ background: rgba(37,99,235,0.05); }}
.category {{ font-weight: bold; color: #60a5fa; }}
.footer {{ text-align: center; color: #64748b; margin-top: 30px; font-size: 12px; }}
</style>
</head>
<body>
<div class="container">
<h1>{title}</h1>
<p>标准: {standard} | 生成时间: {created_at}</p>
<div class="score">{score}</div>
<div class="stats">
<div class="stat"><div class="num">{total}</div><div class="label">总检查项</div></div>
<div class="stat"><div class="num" style="color:#22c55e;">{passed}</div><div class="label">通过</div></div>
<div class="stat"><div class="num" style="color:#ef4444;">{failed}</div><div class="label">失败</div></div>
<div class="stat"><div class="num" style="color:#f59e0b;">{warnings}</div><div class="label">警告</div></div>
</div>
<table>
<tr><th>分类</th><th>名称</th><th>描述</th><th>严重度</th><th>状态</th><th>详情</th><th>修复建议</th></tr>
{rows}
</table>
<div class="footer">GateKeeper - AI安全网络防御系统 | 合规检查报告</div>
</div>
</body>
</html>"""

        rows = ""
        for check in report.checks:
            rows += """<tr>
<td class="category">{category}</td>
<td>{name}</td>
<td>{description}</td>
<td>{severity}</td>
<td>{status}</td>
<td>{detail}</td>
<td>{remediation}</td>
</tr>""".format(
                category=check.category,
                name=check.name,
                description=check.description,
                severity=severity_badge.get(check.severity, check.severity),
                status=status_badge.get(check.status, check.status),
                detail=check.result_detail,
                remediation=check.remediation,
            )

        return html.format(
            title=report.title,
            standard=report._get_standard_name(),
            created_at=report.created_at.strftime("%Y-%m-%d %H:%M:%S"),
            score=report.score,
            score_color=score_color,
            total=report.total_checks,
            passed=report.passed,
            failed=report.failed,
            warnings=report.warnings,
            rows=rows,
        )

    @staticmethod
    def _get_score_color(score: int) -> str:
        """根据分数返回颜色"""
        if score > 80:
            return "#22c55e"
        elif score > 60:
            return "#eab308"
        elif score > 40:
            return "#f97316"
        else:
            return "#ef4444"


# ============================================================
# 单例获取
# ============================================================

_compliance_checker: Optional[ComplianceChecker] = None
_compliance_checker_lock = threading.Lock()


def get_compliance_checker() -> ComplianceChecker:
    """获取合规检查器单例"""
    global _compliance_checker
    if _compliance_checker is None:
        with _compliance_checker_lock:
            if _compliance_checker is None:
                _compliance_checker = ComplianceChecker()
    return _compliance_checker
