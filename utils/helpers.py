"""
GateKeeper - 工具函数
提供时间格式化、IP验证、数据转换等常用工具函数
"""

import time
import math
import re
import functools
from typing import Any, List, Dict, Optional, Callable, TypeVar, Tuple
from datetime import datetime, timedelta
from collections import Counter

T = TypeVar("T")


# ============================================================
# 时间格式化
# ============================================================

def format_datetime(
    dt: Optional[datetime] = None,
    fmt: str = "%Y-%m-%d %H:%M:%S",
) -> str:
    """
    格式化日期时间

    Args:
        dt: datetime对象，None表示当前时间
        fmt: 格式字符串

    Returns:
        格式化后的时间字符串
    """
    if dt is None:
        dt = datetime.now()
    return dt.strftime(fmt)


def format_relative_time(dt: datetime) -> str:
    """
    格式化为相对时间（如"3分钟前"）

    Args:
        dt: datetime对象

    Returns:
        相对时间字符串
    """
    now = datetime.now()
    diff = now - dt

    if diff < timedelta(seconds=60):
        return "刚刚"
    elif diff < timedelta(hours=1):
        return "{}分钟前".format(int(diff.total_seconds() / 60))
    elif diff < timedelta(days=1):
        return "{}小时前".format(int(diff.total_seconds() / 3600))
    elif diff < timedelta(weeks=1):
        return "{}天前".format(diff.days)
    elif diff < timedelta(days=30):
        return "{}周前".format(diff.days // 7)
    else:
        return dt.strftime("%Y-%m-%d")


def parse_datetime(date_str: str, fmt: str = "%Y-%m-%d %H:%M:%S") -> Optional[datetime]:
    """
    解析日期时间字符串

    Args:
        date_str: 日期字符串
        fmt: 格式字符串

    Returns:
        datetime对象或None
    """
    try:
        return datetime.strptime(date_str, fmt)
    except (ValueError, TypeError):
        return None


def timestamp_to_datetime(timestamp: float) -> datetime:
    """将时间戳转换为datetime"""
    return datetime.fromtimestamp(timestamp)


# ============================================================
# 数据格式化
# ============================================================

def format_bytes(size: int, precision: int = 1) -> str:
    """
    格式化字节数为可读字符串

    Args:
        size: 字节数
        precision: 小数精度

    Returns:
        格式化后的字符串（如 "1.5 GB"）
    """
    if size == 0:
        return "0 B"

    units = ["B", "KB", "MB", "GB", "TB", "PB"]
    index = 0
    size_float = float(size)

    while size_float >= 1024 and index < len(units) - 1:
        size_float /= 1024
        index += 1

    return "{:.{precision}f} {}".format(size_float, units[index])


def format_number(num: int) -> str:
    """格式化数字（添加千位分隔符）"""
    return "{:,}".format(num)


def format_percentage(value: float, precision: int = 1) -> str:
    """格式化百分比"""
    return "{:.{precision}f}%".format(value)


def format_duration(seconds: float) -> str:
    """
    格式化持续时间

    Args:
        seconds: 秒数

    Returns:
        格式化后的持续时间字符串
    """
    if seconds < 60:
        return "{:.0f}秒".format(seconds)
    elif seconds < 3600:
        minutes = int(seconds / 60)
        secs = int(seconds % 60)
        return "{}分{}秒".format(minutes, secs)
    elif seconds < 86400:
        hours = int(seconds / 3600)
        minutes = int((seconds % 3600) / 60)
        return "{}小时{}分".format(hours, minutes)
    else:
        days = int(seconds / 86400)
        hours = int((seconds % 86400) / 3600)
        return "{}天{}小时".format(days, hours)


# ============================================================
# 验证函数
# ============================================================

def validate_ip(ip_address: str) -> bool:
    """
    验证IPv4地址格式

    Args:
        ip_address: IP地址字符串

    Returns:
        是否是有效的IPv4地址
    """
    import ipaddress
    try:
        ipaddress.IPv4Address(ip_address)
        return True
    except (ValueError, ipaddress.AddressValueError):
        return False


def validate_ipv6(ip_address: str) -> bool:
    """验证IPv6地址格式"""
    import ipaddress
    try:
        ipaddress.IPv6Address(ip_address)
        return True
    except (ValueError, ipaddress.AddressValueError):
        return False


def validate_cidr(cidr: str) -> bool:
    """
    验证CIDR格式

    Args:
        cidr: CIDR字符串（如 "192.168.1.0/24"）

    Returns:
        是否是有效的CIDR
    """
    import ipaddress
    try:
        ipaddress.ip_network(cidr, strict=False)
        return True
    except ValueError:
        return False


def validate_port(port: int) -> bool:
    """
    验证端口号

    Args:
        port: 端口号

    Returns:
        是否是有效的端口号（1-65535）
    """
    return isinstance(port, int) and 1 <= port <= 65535


def validate_email(email: str) -> bool:
    """
    验证邮箱地址格式

    Args:
        email: 邮箱地址

    Returns:
        是否是有效的邮箱格式
    """
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, email))


def validate_domain(domain: str) -> bool:
    """验证域名格式"""
    pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, domain))


def validate_mac(mac: str) -> bool:
    """验证MAC地址格式"""
    pattern = r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$'
    return bool(re.match(pattern, mac))


# ============================================================
# 数据处理
# ============================================================

def calculate_entropy(data: List) -> float:
    """
    计算信息熵

    Args:
        data: 数据列表

    Returns:
        熵值
    """
    if not data:
        return 0.0

    counts = Counter(data)
    total = len(data)
    entropy = 0.0

    for count in counts.values():
        if count > 0:
            probability = count / total
            entropy -= probability * math.log2(probability)

    return round(entropy, 4)


def truncate_string(s: str, max_length: int = 100, suffix: str = "...") -> str:
    """
    截断字符串

    Args:
        s: 原始字符串
        max_length: 最大长度
        suffix: 截断后缀

    Returns:
        截断后的字符串
    """
    if len(s) <= max_length:
        return s
    return s[: max_length - len(suffix)] + suffix


def safe_int(value: Any, default: int = 0) -> int:
    """安全转换为整数"""
    try:
        return int(value)
    except (ValueError, TypeError):
        return default


def safe_float(value: Any, default: float = 0.0) -> float:
    """安全转换为浮点数"""
    try:
        return float(value)
    except (ValueError, TypeError):
        return default


def dict_merge(base: Dict, override: Dict) -> Dict:
    """
    深度合并字典

    Args:
        base: 基础字典
        override: 覆盖字典

    Returns:
        合并后的新字典
    """
    result = base.copy()
    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = dict_merge(result[key], value)
        else:
            result[key] = value
    return result


def chunk_list(lst: List, chunk_size: int) -> List[List]:
    """
    将列表分割为指定大小的块

    Args:
        lst: 原始列表
        chunk_size: 寒大小

    Returns:
        分割后的列表
    """
    return [lst[i: i + chunk_size] for i in range(0, len(lst), chunk_size)]


def flatten_dict(d: Dict, parent_key: str = "", sep: str = ".") -> Dict:
    """
    扁平化嵌套字典

    Args:
        d: 嵌套字典
        parent_key: 父键前缀
        sep: 分隔符

    Returns:
        扁平化的字典
    """
    items = []
    for key, value in d.items():
        new_key = "{}{}{}".format(parent_key, sep, key) if parent_key else key
        if isinstance(value, dict):
            items.extend(flatten_dict(value, new_key, sep).items())
        else:
            items.append((new_key, value))
    return dict(items)


# ============================================================
# 装饰器和工具
# ============================================================

def retry(max_retries: int = 3, delay: float = 1.0, backoff: float = 2.0):
    """
    重试装饰器

    Args:
        max_retries: 最大重试次数
        delay: 初始延迟（秒）
        backoff: 退避因子

    Returns:
        装饰器函数
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            current_delay = delay
            last_exception = None

            for attempt in range(max_retries + 1):
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    last_exception = e
                    if attempt < max_retries:
                        time.sleep(current_delay)
                        current_delay *= backoff

            raise last_exception

        return wrapper
    return decorator


def timed(func: Callable) -> Callable:
    """计时装饰器，记录函数执行时间"""
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        start = time.time()
        result = func(*args, **kwargs)
        elapsed = time.time() - start
        print("{} 执行耗时: {:.4f}秒".format(func.__name__, elapsed))
        return result
    return wrapper


def rate_limit(max_calls: int, period: float = 60.0):
    """
    频率限制装饰器

    Args:
        max_calls: 最大调用次数
        period: 时间窗口（秒）
    """
    def decorator(func: Callable) -> Callable:
        calls = []

        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            now = time.time()
            # 清理过期记录
            calls[:] = [t for t in calls if now - t < period]

            if len(calls) >= max_calls:
                raise RuntimeError("频率限制: {}次/{}秒".format(max_calls, period))

            calls.append(now)
            return func(*args, **kwargs)

        return wrapper
    return decorator
