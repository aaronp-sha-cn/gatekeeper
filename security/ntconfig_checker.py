"""
NTConfigChecker - 网络设备安全基线排查工具
基于AI大模型分析网络设备配置，找出不合规项
"""

import os
import re
import json
import hashlib
import threading
from datetime import datetime
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional, Any
from enum import Enum

from config.logging_config import get_logger

logger = get_logger("ntconfig_checker")


class DeviceVendor(Enum):
    """设备厂商"""
    CISCO = "cisco"
    HUAWEI = "huawei"
    H3C = "h3c"
    JUNIPER = "juniper"
    ARISTA = "arista"
    OTHER = "other"


class CheckSeverity(Enum):
    """检查结果严重程度"""
    PASS = "pass"
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class CheckStatus(Enum):
    """检查状态"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass
class BaselineRule:
    """基线检查规则"""
    id: str
    name: str
    category: str  # 账户管理/访问控制/日志审计/网络服务/安全加固/其他
    description: str
    check_prompt: str  # AI检查提示词
    vendor: str = "all"  # 适用厂商: all/cisco/huawei/h3c
    severity: str = "medium"  # 默认严重程度
    reference: str = ""  # 参考标准（如等保2.0、CIS等）
    enabled: bool = True
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "BaselineRule":
        return cls(**data)


@dataclass
class CheckResult:
    """检查结果"""
    rule_id: str
    rule_name: str
    category: str
    severity: str
    status: str  # pass/fail/warning/not_applicable
    finding: str  # 发现的问题描述
    evidence: str  # 配置证据
    recommendation: str  # 整改建议
    raw_response: str = ""  # AI原始响应


@dataclass
class DeviceConfig:
    """设备配置"""
    id: str
    filename: str
    vendor: str
    device_type: str  # router/switch/firewall/other
    hostname: str
    config_text: str
    config_lines: List[str] = field(default_factory=list)
    uploaded_at: str = field(default_factory=lambda: datetime.now().isoformat())
    # 设备连接信息（用于远程检查）
    ip_address: str = ""
    username: str = ""
    password: str = ""

    def to_dict(self) -> dict:
        d = asdict(self)
        d["config_lines_count"] = len(self.config_lines)
        d["config_text_length"] = len(self.config_text)
        del d["config_text"]  # 不返回完整配置
        del d["config_lines"]
        del d["password"]  # 密码不返回前端
        d["has_password"] = bool(self.password)  # 仅返回是否有密码
        return d


@dataclass
class CheckTask:
    """检查任务"""
    id: str
    name: str
    device_configs: List[str]  # 设备配置ID列表
    rules: List[str]  # 规则ID列表
    status: str = CheckStatus.PENDING.value
    progress: int = 0
    total_checks: int = 0
    completed_checks: int = 0
    results: List[dict] = field(default_factory=list)
    started_at: str = ""
    completed_at: str = ""
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    error_message: str = ""

    def to_dict(self) -> dict:
        d = asdict(self)
        d["results_count"] = len(self.results)
        return d


# 内置基线规则库（参考等保2.0和CIS Benchmark）
DEFAULT_BASELINE_RULES = [
    # 账户管理
    BaselineRule(
        id="BL001",
        name="特权账户密码复杂度",
        category="账户管理",
        description="检查特权账户密码是否满足复杂度要求（长度>=8，包含大小写字母、数字、特殊字符）",
        check_prompt="""检查设备配置中的密码策略设置，分析：
1. 是否配置了密码最小长度要求（建议>=8位）
2. 是否要求密码包含大写字母
3. 是否要求密码包含小写字母
4. 是否要求密码包含数字
5. 是否要求密码包含特殊字符
6. 密码是否明文存储

请根据配置输出检查结果，格式：
状态: [pass/fail]
发现: [具体问题描述]
建议: [整改建议]""",
        vendor="all",
        severity="high",
        reference="等保2.0-身份鉴别"
    ),
    BaselineRule(
        id="BL002",
        name="账户锁定策略",
        category="账户管理",
        description="检查是否配置登录失败锁定策略",
        check_prompt="""检查设备配置中的账户锁定策略：
1. 是否配置登录失败次数限制（建议<=5次）
2. 是否配置锁定时间（建议>=15分钟）
3. 是否配置账户超时自动退出

请根据配置输出检查结果，格式：
状态: [pass/fail]
发现: [具体问题描述]
建议: [整改建议]""",
        vendor="all",
        severity="medium",
        reference="等保2.0-身份鉴别"
    ),
    BaselineRule(
        id="BL003",
        name="默认账户处理",
        category="账户管理",
        description="检查是否修改或删除了默认账户",
        check_prompt="""检查设备配置中的默认账户：
1. 是否存在默认账户（如admin、root、cisco、huawei等）
2. 默认账户是否已修改密码
3. 不使用的默认账户是否已禁用或删除

请根据配置输出检查结果，格式：
状态: [pass/fail]
发现: [具体问题描述]
建议: [整改建议]""",
        vendor="all",
        severity="high",
        reference="CIS Benchmark"
    ),
    # 访问控制
    BaselineRule(
        id="BL004",
        name="远程管理访问控制",
        category="访问控制",
        description="检查远程管理（SSH/Telnet）访问控制配置",
        check_prompt="""检查设备配置中的远程管理访问控制：
1. 是否禁用了Telnet（建议仅使用SSH）
2. SSH版本是否为v2
3. 是否配置了管理访问ACL限制
4. 是否配置了允许管理的源IP地址
5. 是否禁用了不必要的管理协议

请根据配置输出检查结果，格式：
状态: [pass/fail]
发现: [具体问题描述]
建议: [整改建议]""",
        vendor="all",
        severity="high",
        reference="等保2.0-访问控制"
    ),
    BaselineRule(
        id="BL005",
        name="特权模式访问控制",
        category="访问控制",
        description="检查特权模式（enable/privileged）访问控制",
        check_prompt="""检查设备配置中的特权模式访问控制：
1. 是否配置了特权模式密码
2. 特权密码是否加密存储
3. 是否配置了特权级别分级
4. 是否使用enable secret而非enable password

请根据配置输出检查结果，格式：
状态: [pass/fail]
发现: [具体问题描述]
建议: [整改建议]""",
        vendor="cisco",
        severity="high",
        reference="CIS Cisco Benchmark"
    ),
    BaselineRule(
        id="BL006",
        name="Console访问控制",
        category="访问控制",
        description="检查Console端口访问控制配置",
        check_prompt="""检查设备配置中的Console访问控制：
1. 是否配置了Console密码
2. 是否配置了Console超时
3. 是否配置了Console登录认证

请根据配置输出检查结果，格式：
状态: [pass/fail]
发现: [具体问题描述]
建议: [整改建议]""",
        vendor="all",
        severity="medium",
        reference="CIS Benchmark"
    ),
    # 日志审计
    BaselineRule(
        id="BL007",
        name="日志服务器配置",
        category="日志审计",
        description="检查是否配置了远程日志服务器",
        check_prompt="""检查设备配置中的日志服务器配置：
1. 是否配置了远程Syslog服务器
2. 是否配置了日志级别
3. 是否配置了日志源地址
4. 是否配置了日志时间戳

请根据配置输出检查结果，格式：
状态: [pass/fail]
发现: [具体问题描述]
建议: [整改建议]""",
        vendor="all",
        severity="medium",
        reference="等保2.0-安全审计"
    ),
    BaselineRule(
        id="BL008",
        name="操作日志记录",
        category="日志审计",
        description="检查是否启用了操作命令审计日志",
        check_prompt="""检查设备配置中的操作日志配置：
1. 是否启用了命令审计日志
2. 是否记录了用户操作命令
3. 日志是否包含时间戳和用户信息
4. 是否配置了日志缓冲区大小

请根据配置输出检查结果，格式：
状态: [pass/fail]
发现: [具体问题描述]
建议: [整改建议]""",
        vendor="all",
        severity="medium",
        reference="等保2.0-安全审计"
    ),
    BaselineRule(
        id="BL009",
        name="NTP时间同步",
        category="日志审计",
        description="检查是否配置了NTP时间同步",
        check_prompt="""检查设备配置中的NTP配置：
1. 是否配置了NTP服务器
2. NTP服务器是否可达
3. 是否配置了时区
4. 是否配置了NTP认证

请根据配置输出检查结果，格式：
状态: [pass/fail]
发现: [具体问题描述]
建议: [整改建议]""",
        vendor="all",
        severity="low",
        reference="CIS Benchmark"
    ),
    # 网络服务
    BaselineRule(
        id="BL010",
        name="不必要服务禁用",
        category="网络服务",
        description="检查是否禁用了不必要的服务",
        check_prompt="""检查设备配置中是否禁用了不必要的服务：
1. CDP/LLDP是否必要
2. HTTP服务是否禁用
3. SNMP是否必要，是否配置了community
4. BOOTP/DHCP服务
5. DNS解析服务
6. Finger服务
7. 其他不必要的服务

请根据配置输出检查结果，格式：
状态: [pass/fail]
发现: [具体问题描述]
建议: [整改建议]""",
        vendor="all",
        severity="medium",
        reference="CIS Benchmark"
    ),
    BaselineRule(
        id="BL011",
        name="SNMP安全配置",
        category="网络服务",
        description="检查SNMP服务安全配置",
        check_prompt="""检查设备配置中的SNMP安全配置：
1. SNMP版本（建议v3）
2. Community字符串是否为默认值（public/private）
3. 是否配置了SNMP访问控制
4. SNMPv3是否配置了认证和加密

请根据配置输出检查结果，格式：
状态: [pass/fail]
发现: [具体问题描述]
建议: [整改建议]""",
        vendor="all",
        severity="high",
        reference="等保2.0"
    ),
    BaselineRule(
        id="BL012",
        name="路由协议安全",
        category="网络服务",
        description="检查路由协议安全配置",
        check_prompt="""检查设备配置中的路由协议安全：
1. 是否启用了路由协议认证
2. 是否配置了被动接口
3. 是否过滤了路由更新
4. 是否配置了路由协议日志

请根据配置输出检查结果，格式：
状态: [pass/fail]
发现: [具体问题描述]
建议: [整改建议]""",
        vendor="all",
        severity="medium",
        reference="CIS Benchmark"
    ),
    # 安全加固
    BaselineRule(
        id="BL013",
        name="Banner配置",
        category="安全加固",
        description="检查登录Banner是否包含敏感信息",
        check_prompt="""检查设备配置中的Banner设置：
1. 是否配置了登录Banner
2. Banner是否包含敏感信息（如公司名称、设备型号、IP地址等）
3. Banner是否包含法律免责声明

请根据配置输出检查结果，格式：
状态: [pass/fail]
发现: [具体问题描述]
建议: [整改建议]""",
        vendor="all",
        severity="low",
        reference="CIS Benchmark"
    ),
    BaselineRule(
        id="BL014",
        name="源地址欺骗防护",
        category="安全加固",
        description="检查是否配置了源地址欺骗防护",
        check_prompt="""检查设备配置中的源地址欺骗防护：
1. 是否配置了uRPF（单播反向路径转发）
2. 是否配置了源IP地址过滤
3. 是否配置了入口过滤

请根据配置输出检查结果，格式：
状态: [pass/fail]
发现: [具体问题描述]
建议: [整改建议]""",
        vendor="all",
        severity="medium",
        reference="等保2.0"
    ),
    BaselineRule(
        id="BL015",
        name="控制平面保护",
        category="安全加固",
        description="检查是否配置了控制平面保护",
        check_prompt="""检查设备配置中的控制平面保护：
1. 是否配置了CoPP（控制平面策略）
2. 是否限制了ICMP到控制平面
3. 是否限制了管理协议访问

请根据配置输出检查结果，格式：
状态: [pass/fail]
发现: [具体问题描述]
建议: [整改建议]""",
        vendor="cisco",
        severity="medium",
        reference="CIS Cisco Benchmark"
    ),
]


class NTConfigChecker:
    """网络设备配置安全基线检查器"""

    def __init__(self):
        self.rules: Dict[str, BaselineRule] = {}
        self.devices: Dict[str, DeviceConfig] = {}
        self.tasks: Dict[str, CheckTask] = {}
        self._lock = threading.Lock()
        self._running_task: Optional[str] = None
        self._stop_flag = False
        self._data_file = "data/ntconfig_data.json"

        # 加载内置规则
        self._load_default_rules()
        # 加载持久化数据
        self._load_data()

        logger.info(f"NTConfigChecker初始化完成，已加载{len(self.rules)}条规则")

    def _load_default_rules(self):
        """加载默认基线规则"""
        for rule in DEFAULT_BASELINE_RULES:
            self.rules[rule.id] = rule

    def _load_data(self):
        """加载持久化数据"""
        try:
            if os.path.exists(self._data_file):
                with open(self._data_file, "r", encoding="utf-8") as f:
                    data = json.load(f)

                # 加载自定义规则
                for rule_data in data.get("custom_rules", []):
                    rule = BaselineRule.from_dict(rule_data)
                    if rule.id not in self.rules:
                        self.rules[rule.id] = rule

                # 加载设备配置
                for dev_data in data.get("devices", []):
                    dev = DeviceConfig(**dev_data)
                    self.devices[dev.id] = dev

                # 加载任务
                for task_data in data.get("tasks", []):
                    task = CheckTask(**task_data)
                    self.tasks[task.id] = task

                logger.info(f"从{self._data_file}加载数据完成")
        except Exception as e:
            logger.warning(f"加载数据失败: {e}")

    def _save_data(self):
        """保存持久化数据"""
        try:
            os.makedirs(os.path.dirname(self._data_file), exist_ok=True)

            custom_rules = [r.to_dict() for r in self.rules.values()
                           if r.id not in [dr.id for dr in DEFAULT_BASELINE_RULES]]

            data = {
                "custom_rules": custom_rules,
                "devices": [d.to_dict() for d in self.devices.values()],
                "tasks": [t.to_dict() for t in self.tasks.values()],
            }

            with open(self._data_file, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)

        except Exception as e:
            logger.error(f"保存数据失败: {e}")

    # ==================== 规则管理 ====================

    def add_rule(self, rule: BaselineRule) -> bool:
        """添加规则"""
        with self._lock:
            if rule.id in self.rules:
                return False
            self.rules[rule.id] = rule
            self._save_data()
            return True

    def update_rule(self, rule_id: str, updates: dict) -> bool:
        """更新规则"""
        with self._lock:
            if rule_id not in self.rules:
                return False
            rule = self.rules[rule_id]
            for key, value in updates.items():
                if hasattr(rule, key):
                    setattr(rule, key, value)
            self._save_data()
            return True

    def delete_rule(self, rule_id: str) -> bool:
        """删除规则（仅限自定义规则）"""
        with self._lock:
            if rule_id not in self.rules:
                return False
            if rule_id in [r.id for r in DEFAULT_BASELINE_RULES]:
                return False  # 不允许删除内置规则
            del self.rules[rule_id]
            self._save_data()
            return True

    def get_rules(self, category: str = None, vendor: str = None) -> List[BaselineRule]:
        """获取规则列表"""
        rules = list(self.rules.values())
        if category:
            rules = [r for r in rules if r.category == category]
        if vendor and vendor != "all":
            rules = [r for r in rules if r.vendor == "all" or r.vendor == vendor]
        return rules

    def get_rule(self, rule_id: str) -> Optional[BaselineRule]:
        """获取单个规则"""
        return self.rules.get(rule_id)

    def toggle_rule(self, rule_id: str, enabled: bool) -> bool:
        """启用/禁用规则"""
        with self._lock:
            if rule_id not in self.rules:
                return False
            self.rules[rule_id].enabled = enabled
            self._save_data()
            return True

    # ==================== 设备配置管理 ====================

    def _detect_vendor(self, config_text: str) -> str:
        """检测设备厂商"""
        config_lower = config_text.lower()

        # Cisco特征
        if any(kw in config_lower for kw in ["cisco", "ios", "enable password", "show running-config",
                                               "interface gigabitethernet", "interface fastethernet"]):
            return DeviceVendor.CISCO.value

        # Huawei特征
        if any(kw in config_lower for kw in ["huawei", "vrp", "display current-configuration",
                                               "interface gigabitethernet", "sysname"]):
            return DeviceVendor.HUAWEI.value

        # H3C特征
        if any(kw in config_lower for kw in ["h3c", "comware", "display current-configuration",
                                               "irf-port"]):
            return DeviceVendor.H3C.value

        # Juniper特征
        if any(kw in config_lower for kw in ["juniper", "junos", "set interfaces",
                                               "set system"]):
            return DeviceVendor.JUNIPER.value

        return DeviceVendor.OTHER.value

    def _detect_device_type(self, config_text: str) -> str:
        """检测设备类型"""
        config_lower = config_text.lower()

        # 防火墙特征
        if any(kw in config_lower for kw in ["firewall", "asa", "firepower", "paloalto",
                                               "fortigate", "zone", "policy"]):
            return "firewall"

        # 路由器特征
        if any(kw in config_lower for kw in ["router ospf", "router bgp", "router rip",
                                               "ip route", "routing-table"]):
            return "router"

        # 交换机特征
        if any(kw in config_lower for kw in ["vlan", "switchport", "spanning-tree",
                                               "port-channel", "trunk"]):
            return "switch"

        return "other"

    def _extract_hostname(self, config_text: str, vendor: str) -> str:
        """提取主机名"""
        lines = config_text.split("\n")

        if vendor == DeviceVendor.CISCO.value:
            for line in lines:
                if line.strip().startswith("hostname "):
                    return line.strip().split()[-1]

        elif vendor in [DeviceVendor.HUAWEI.value, DeviceVendor.H3C.value]:
            for line in lines:
                if line.strip().startswith("sysname "):
                    return line.strip().split()[-1]

        # 尝试从其他位置提取
        for line in lines[:20]:
            if "hostname" in line.lower() or "sysname" in line.lower():
                parts = line.strip().split()
                if len(parts) >= 2:
                    return parts[-1]

        return "unknown"

    def upload_config(self, filename: str, config_text: str,
                      ip_address: str = "", username: str = "", password: str = "") -> DeviceConfig:
        """上传设备配置，支持指定设备连接信息"""
        # 生成ID
        config_id = hashlib.md5(f"{filename}_{datetime.now().isoformat()}".encode()).hexdigest()[:12]

        # 检测厂商和类型
        vendor = self._detect_vendor(config_text)
        device_type = self._detect_device_type(config_text)
        hostname = self._extract_hostname(config_text, vendor)

        # 解析配置行
        config_lines = [line.rstrip() for line in config_text.split("\n") if line.strip()]

        device = DeviceConfig(
            id=config_id,
            filename=filename,
            vendor=vendor,
            device_type=device_type,
            hostname=hostname,
            config_text=config_text,
            config_lines=config_lines,
            ip_address=ip_address,
            username=username,
            password=password,
        )

        with self._lock:
            self.devices[config_id] = device
            self._save_data()

        logger.info(f"上传设备配置: {filename}, 厂商={vendor}, 类型={device_type}, 主机名={hostname}")
        return device

    def get_devices(self) -> List[DeviceConfig]:
        """获取设备列表"""
        return list(self.devices.values())

    def get_device(self, device_id: str) -> Optional[DeviceConfig]:
        """获取设备配置"""
        return self.devices.get(device_id)

    def delete_device(self, device_id: str) -> bool:
        """删除设备配置"""
        with self._lock:
            if device_id not in self.devices:
                return False
            del self.devices[device_id]
            self._save_data()
            return True

    # ==================== 检查任务 ====================

    def create_task(self, name: str, device_ids: List[str], rule_ids: List[str]) -> CheckTask:
        """创建检查任务"""
        task_id = hashlib.md5(f"{name}_{datetime.now().isoformat()}".encode()).hexdigest()[:12]

        task = CheckTask(
            id=task_id,
            name=name,
            device_configs=device_ids,
            rules=rule_ids,
            total_checks=len(device_ids) * len(rule_ids),
        )

        with self._lock:
            self.tasks[task_id] = task
            self._save_data()

        logger.info(f"创建检查任务: {name}, 设备数={len(device_ids)}, 规则数={len(rule_ids)}")
        return task

    def start_task(self, task_id: str, ai_provider: str = "default") -> bool:
        """启动检查任务"""
        with self._lock:
            if task_id not in self.tasks:
                return False
            if self._running_task:
                return False  # 已有任务在运行

            task = self.tasks[task_id]
            task.status = CheckStatus.RUNNING.value
            task.started_at = datetime.now().isoformat()
            task.progress = 0
            task.completed_checks = 0
            task.results = []
            self._running_task = task_id
            self._stop_flag = False

        # 启动检查线程
        thread = threading.Thread(
            target=self._run_checks,
            args=(task_id, ai_provider),
            daemon=True
        )
        thread.start()

        logger.info(f"启动检查任务: {task_id}")
        return True

    def stop_task(self, task_id: str) -> bool:
        """停止检查任务"""
        with self._lock:
            if self._running_task != task_id:
                return False
            self._stop_flag = True
        return True

    def _run_checks(self, task_id: str, ai_provider: str):
        """执行检查（后台线程）"""
        try:
            task = self.tasks[task_id]

            for device_id in task.device_configs:
                if self._stop_flag:
                    break

                device = self.devices.get(device_id)
                if not device:
                    continue

                for rule_id in task.rules:
                    if self._stop_flag:
                        break

                    rule = self.rules.get(rule_id)
                    if not rule or not rule.enabled:
                        continue

                    # 检查厂商匹配
                    if rule.vendor != "all" and rule.vendor != device.vendor:
                        continue

                    # 执行检查
                    result = self._check_config(device, rule, ai_provider)

                    with self._lock:
                        task.results.append(result)
                        task.completed_checks += 1
                        task.progress = int(task.completed_checks / task.total_checks * 100)

            # 任务完成
            with self._lock:
                task.status = CheckStatus.COMPLETED.value
                task.completed_at = datetime.now().isoformat()
                task.progress = 100
                self._running_task = None
                self._save_data()

            logger.info(f"检查任务完成: {task_id}, 结果数={len(task.results)}")

        except Exception as e:
            logger.error(f"检查任务失败: {task_id}, 错误={e}")
            with self._lock:
                task = self.tasks.get(task_id)
                if task:
                    task.status = CheckStatus.FAILED.value
                    task.error_message = str(e)
                    self._running_task = None
                    self._save_data()

    def _check_config(self, device: DeviceConfig, rule: BaselineRule,
                      ai_provider: str) -> dict:
        """执行单条规则检查"""
        try:
            # 尝试使用AI引擎
            ai_response = self._call_ai(device, rule, ai_provider)

            if ai_response:
                # 解析AI响应
                result = self._parse_ai_response(rule, device, ai_response)
            else:
                # 回退到规则匹配
                result = self._rule_based_check(device, rule)

            return result

        except Exception as e:
            logger.error(f"检查失败: 设备={device.hostname}, 规则={rule.id}, 错误={e}")
            return {
                "device_id": device.id,
                "device_name": device.hostname,
                "rule_id": rule.id,
                "rule_name": rule.name,
                "category": rule.category,
                "severity": rule.severity,
                "status": "error",
                "finding": f"检查过程出错: {str(e)}",
                "evidence": "",
                "recommendation": "",
                "checked_at": datetime.now().isoformat(),
            }

    def _call_ai(self, device: DeviceConfig, rule: BaselineRule,
                 ai_provider: str) -> Optional[str]:
        """调用AI引擎分析配置"""
        try:
            from ai_engine.llm_provider import get_llm_provider

            llm = get_llm_provider()
            if not llm or not llm.is_available():
                return None

            # 构建提示词
            prompt = f"""你是一个网络安全专家，正在检查网络设备配置的安全性。

设备信息：
- 厂商: {device.vendor}
- 类型: {device.device_type}
- 主机名: {device.hostname}

检查规则：
- 名称: {rule.name}
- 类别: {rule.category}
- 描述: {rule.description}
- 参考标准: {rule.reference}

检查要求：
{rule.check_prompt}

设备配置：
```
{device.config_text[:8000]}
```

请根据上述配置进行分析，输出检查结果。格式要求：
状态: [pass/fail]
发现: [具体问题描述，如果没有问题则写"符合要求"]
建议: [整改建议，如果符合要求则写"无需整改"]
证据: [相关配置片段]
"""

            response = llm.chat(prompt)
            return response

        except Exception as e:
            logger.warning(f"AI调用失败: {e}")
            return None

    def _parse_ai_response(self, rule: BaselineRule, device: DeviceConfig,
                          response: str) -> dict:
        """解析AI响应"""
        status = "unknown"
        finding = ""
        recommendation = ""
        evidence = ""

        # 解析状态
        status_match = re.search(r"状态\s*[:：]\s*(\w+)", response)
        if status_match:
            status = status_match.group(1).lower()
            if status not in ["pass", "fail", "warning"]:
                status = "unknown"

        # 解析发现
        finding_match = re.search(r"发现\s*[:：]\s*(.+?)(?=建议|证据|$)", response, re.DOTALL)
        if finding_match:
            finding = finding_match.group(1).strip()

        # 解析建议
        rec_match = re.search(r"建议\s*[:：]\s*(.+?)(?=证据|$)", response, re.DOTALL)
        if rec_match:
            recommendation = rec_match.group(1).strip()

        # 解析证据
        ev_match = re.search(r"证据\s*[:：]\s*(.+?)$", response, re.DOTALL)
        if ev_match:
            evidence = ev_match.group(1).strip()

        return {
            "device_id": device.id,
            "device_name": device.hostname,
            "rule_id": rule.id,
            "rule_name": rule.name,
            "category": rule.category,
            "severity": rule.severity,
            "status": status,
            "finding": finding,
            "evidence": evidence,
            "recommendation": recommendation,
            "checked_at": datetime.now().isoformat(),
            "raw_response": response[:500],
        }

    def _rule_based_check(self, device: DeviceConfig, rule: BaselineRule) -> dict:
        """基于规则的检查（AI不可用时的回退方案）"""
        config_lower = device.config_text.lower()
        status = "fail"
        finding = "未找到相关配置"
        evidence = ""
        recommendation = rule.description

        # 简单的关键词匹配
        keywords = {
            "BL001": ["password", "secret", "encryption"],
            "BL004": ["ssh", "telnet", "access-class", "acl"],
            "BL007": ["logging", "syslog", "server"],
            "BL009": ["ntp", "clock", "timezone"],
            "BL011": ["snmp", "community", "public", "private"],
        }

        rule_keywords = keywords.get(rule.id, [])
        found_keywords = [kw for kw in rule_keywords if kw in config_lower]

        if found_keywords:
            status = "warning"
            finding = f"发现相关配置关键词: {', '.join(found_keywords)}，需人工确认"

            # 提取证据
            for line in device.config_lines:
                if any(kw in line.lower() for kw in found_keywords):
                    evidence += line + "\n"
                    if len(evidence) > 500:
                        break

        return {
            "device_id": device.id,
            "device_name": device.hostname,
            "rule_id": rule.id,
            "rule_name": rule.name,
            "category": rule.category,
            "severity": rule.severity,
            "status": status,
            "finding": finding,
            "evidence": evidence[:500],
            "recommendation": recommendation,
            "checked_at": datetime.now().isoformat(),
        }

    def get_task(self, task_id: str) -> Optional[CheckTask]:
        """获取任务"""
        return self.tasks.get(task_id)

    def get_tasks(self) -> List[CheckTask]:
        """获取任务列表"""
        return list(self.tasks.values())

    def delete_task(self, task_id: str) -> bool:
        """删除任务"""
        with self._lock:
            if task_id not in self.tasks:
                return False
            del self.tasks[task_id]
            self._save_data()
            return True

    # ==================== 报告生成 ====================

    def generate_report(self, task_id: str, format: str = "html") -> Optional[str]:
        """生成检查报告"""
        task = self.tasks.get(task_id)
        if not task or task.status != CheckStatus.COMPLETED.value:
            return None

        if format == "html":
            return self._generate_html_report(task)
        elif format == "json":
            return self._generate_json_report(task)
        else:
            return self._generate_html_report(task)

    def _generate_html_report(self, task: CheckTask) -> str:
        """生成HTML报告"""
        # 统计结果
        pass_count = sum(1 for r in task.results if r.get("status") == "pass")
        fail_count = sum(1 for r in task.results if r.get("status") == "fail")
        warning_count = sum(1 for r in task.results if r.get("status") == "warning")

        # 按严重程度统计
        severity_stats = {}
        for r in task.results:
            sev = r.get("severity", "unknown")
            severity_stats[sev] = severity_stats.get(sev, 0) + 1

        html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>安全基线检查报告 - {task.name}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; }}
        h1 {{ color: #333; border-bottom: 2px solid #2563eb; padding-bottom: 10px; }}
        h2 {{ color: #555; margin-top: 30px; }}
        .stats {{ display: flex; gap: 20px; margin: 20px 0; }}
        .stat-card {{ flex: 1; padding: 15px; border-radius: 8px; text-align: center; }}
        .stat-card.pass {{ background: #d1fae5; color: #065f46; }}
        .stat-card.fail {{ background: #fee2e2; color: #991b1b; }}
        .stat-card.warning {{ background: #fef3c7; color: #92400e; }}
        .stat-card h3 {{ margin: 0; font-size: 32px; }}
        .stat-card p {{ margin: 5px 0 0; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background: #f3f4f6; }}
        tr:hover {{ background: #f9fafb; }}
        .status-pass {{ color: #059669; font-weight: bold; }}
        .status-fail {{ color: #dc2626; font-weight: bold; }}
        .status-warning {{ color: #d97706; font-weight: bold; }}
        .severity-high {{ color: #dc2626; }}
        .severity-critical {{ color: #7f1d1d; font-weight: bold; }}
        .footer {{ margin-top: 30px; padding-top: 20px; border-top: 1px solid #ddd; color: #666; font-size: 12px; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>安全基线检查报告</h1>
        <p><strong>任务名称:</strong> {task.name}</p>
        <p><strong>检查时间:</strong> {task.started_at}</p>
        <p><strong>设备数量:</strong> {len(task.device_configs)}</p>
        <p><strong>检查项数:</strong> {task.total_checks}</p>

        <div class="stats">
            <div class="stat-card pass">
                <h3>{pass_count}</h3>
                <p>通过</p>
            </div>
            <div class="stat-card fail">
                <h3>{fail_count}</h3>
                <p>不合规</p>
            </div>
            <div class="stat-card warning">
                <h3>{warning_count}</h3>
                <p>警告</p>
            </div>
        </div>

        <h2>检查结果详情</h2>
        <table>
            <tr>
                <th>设备</th>
                <th>检查项</th>
                <th>类别</th>
                <th>严重程度</th>
                <th>状态</th>
                <th>问题描述</th>
            </tr>
"""

        for r in task.results:
            status_class = f"status-{r.get('status', 'unknown')}"
            severity_class = f"severity-{r.get('severity', 'medium')}"
            html += f"""            <tr>
                <td>{r.get('device_name', '-')}</td>
                <td>{r.get('rule_name', '-')}</td>
                <td>{r.get('category', '-')}</td>
                <td class="{severity_class}">{r.get('severity', '-')}</td>
                <td class="{status_class}">{r.get('status', '-')}</td>
                <td>{r.get('finding', '-')[:100]}</td>
            </tr>
"""

        html += """        </table>

        <div class="footer">
            <p>报告生成时间: """ + datetime.now().isoformat() + """</p>
            <p>GateKeeper - 网络安全基线检查系统</p>
        </div>
    </div>
</body>
</html>"""

        return html

    def _generate_json_report(self, task: CheckTask) -> str:
        """生成JSON报告"""
        report = {
            "task": task.to_dict(),
            "summary": {
                "total": len(task.results),
                "pass": sum(1 for r in task.results if r.get("status") == "pass"),
                "fail": sum(1 for r in task.results if r.get("status") == "fail"),
                "warning": sum(1 for r in task.results if r.get("status") == "warning"),
            },
            "results": task.results,
            "generated_at": datetime.now().isoformat(),
        }
        return json.dumps(report, ensure_ascii=False, indent=2)

    # ==================== 统计信息 ====================

    def get_stats(self) -> dict:
        """获取统计信息"""
        # 规则统计
        rules_by_category = {}
        for rule in self.rules.values():
            cat = rule.category
            rules_by_category[cat] = rules_by_category.get(cat, 0) + 1

        # 设备统计
        devices_by_vendor = {}
        for device in self.devices.values():
            vendor = device.vendor
            devices_by_vendor[vendor] = devices_by_vendor.get(vendor, 0) + 1

        # 任务统计
        tasks_by_status = {}
        for task in self.tasks.values():
            status = task.status
            tasks_by_status[status] = tasks_by_status.get(status, 0) + 1

        return {
            "rules": {
                "total": len(self.rules),
                "enabled": sum(1 for r in self.rules.values() if r.enabled),
                "by_category": rules_by_category,
            },
            "devices": {
                "total": len(self.devices),
                "by_vendor": devices_by_vendor,
            },
            "tasks": {
                "total": len(self.tasks),
                "by_status": tasks_by_status,
            },
        }


# 单例
_ntconfig_checker: Optional[NTConfigChecker] = None
_ntconfig_checker_lock = threading.Lock()


def get_ntconfig_checker() -> NTConfigChecker:
    """获取NTConfigChecker单例"""
    global _ntconfig_checker
    if _ntconfig_checker is None:
        with _ntconfig_checker_lock:
            if _ntconfig_checker is None:
                _ntconfig_checker = NTConfigChecker()
    return _ntconfig_checker
