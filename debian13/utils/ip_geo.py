"""
GateKeeper - IP 归属地查询工具
纯本地实现，不依赖外部 API
支持私有 IP 识别、中国主要省份/城市经纬度映射
"""

import ipaddress
import random
import hashlib
from typing import Optional, Dict, List, Any

logger = __import__("config.logging_config", fromlist=["get_logger"]).get_logger("utils.ip_geo")


# ============================================================
# 中国主要省份/城市经纬度映射表
# ============================================================

CHINA_PROVINCE_GEO = {
    # 直辖市
    "北京": {
        "province": "北京",
        "city": "北京",
        "latitude": 39.9042,
        "longitude": 116.4074,
        "isp": "联通/电信/移动",
    },
    "上海": {
        "province": "上海",
        "city": "上海",
        "latitude": 31.2304,
        "longitude": 121.4737,
        "isp": "联通/电信/移动",
    },
    "天津": {
        "province": "天津",
        "city": "天津",
        "latitude": 39.3434,
        "longitude": 117.3616,
        "isp": "联通/电信/移动",
    },
    "重庆": {
        "province": "重庆",
        "city": "重庆",
        "latitude": 29.5630,
        "longitude": 106.5516,
        "isp": "联通/电信/移动",
    },
    # 华北
    "河北": {
        "province": "河北",
        "city": "石家庄",
        "latitude": 38.0428,
        "longitude": 114.5149,
        "isp": "联通/电信",
    },
    "山西": {
        "province": "山西",
        "city": "太原",
        "latitude": 37.8706,
        "longitude": 112.5489,
        "isp": "联通",
    },
    "内蒙古": {
        "province": "内蒙古",
        "city": "呼和浩特",
        "latitude": 40.8414,
        "longitude": 111.7519,
        "isp": "联通/电信",
    },
    # 东北
    "辽宁": {
        "province": "辽宁",
        "city": "沈阳",
        "latitude": 41.8057,
        "longitude": 123.4315,
        "isp": "联通",
    },
    "吉林": {
        "province": "吉林",
        "city": "长春",
        "latitude": 43.8171,
        "longitude": 125.3235,
        "isp": "联通",
    },
    "黑龙江": {
        "province": "黑龙江",
        "city": "哈尔滨",
        "latitude": 45.8038,
        "longitude": 126.5350,
        "isp": "联通",
    },
    # 华东
    "江苏": {
        "province": "江苏",
        "city": "南京",
        "latitude": 32.0603,
        "longitude": 118.7969,
        "isp": "电信/联通",
    },
    "浙江": {
        "province": "浙江",
        "city": "杭州",
        "latitude": 30.2741,
        "longitude": 120.1551,
        "isp": "电信",
    },
    "安徽": {
        "province": "安徽",
        "city": "合肥",
        "latitude": 31.8206,
        "longitude": 117.2272,
        "isp": "电信",
    },
    "福建": {
        "province": "福建",
        "city": "福州",
        "latitude": 26.0745,
        "longitude": 119.2965,
        "isp": "电信",
    },
    "江西": {
        "province": "江西",
        "city": "南昌",
        "latitude": 28.6820,
        "longitude": 115.8579,
        "isp": "电信/移动",
    },
    "山东": {
        "province": "山东",
        "city": "济南",
        "latitude": 36.6512,
        "longitude": 116.9972,
        "isp": "联通/电信",
    },
    # 华南
    "广东": {
        "province": "广东",
        "city": "广州",
        "latitude": 23.1291,
        "longitude": 113.2644,
        "isp": "电信",
    },
    "广西": {
        "province": "广西",
        "city": "南宁",
        "latitude": 22.8170,
        "longitude": 108.3665,
        "isp": "电信",
    },
    "海南": {
        "province": "海南",
        "city": "海口",
        "latitude": 20.0174,
        "longitude": 110.3492,
        "isp": "电信",
    },
    # 华中
    "河南": {
        "province": "河南",
        "city": "郑州",
        "latitude": 34.7466,
        "longitude": 113.6254,
        "isp": "联通/电信",
    },
    "湖北": {
        "province": "湖北",
        "city": "武汉",
        "latitude": 30.5928,
        "longitude": 114.3055,
        "isp": "电信",
    },
    "湖南": {
        "province": "湖南",
        "city": "长沙",
        "latitude": 28.2282,
        "longitude": 112.9388,
        "isp": "电信",
    },
    # 西南
    "四川": {
        "province": "四川",
        "city": "成都",
        "latitude": 30.5728,
        "longitude": 104.0668,
        "isp": "电信",
    },
    "贵州": {
        "province": "贵州",
        "city": "贵阳",
        "latitude": 26.6470,
        "longitude": 106.6302,
        "isp": "电信",
    },
    "云南": {
        "province": "云南",
        "city": "昆明",
        "latitude": 25.0389,
        "longitude": 102.7183,
        "isp": "电信",
    },
    "西藏": {
        "province": "西藏",
        "city": "拉萨",
        "latitude": 29.6500,
        "longitude": 91.1000,
        "isp": "电信",
    },
    # 西北
    "陕西": {
        "province": "陕西",
        "city": "西安",
        "latitude": 34.3416,
        "longitude": 108.9398,
        "isp": "电信",
    },
    "甘肃": {
        "province": "甘肃",
        "city": "兰州",
        "latitude": 36.0611,
        "longitude": 103.8343,
        "isp": "电信",
    },
    "青海": {
        "province": "青海",
        "city": "西宁",
        "latitude": 36.6171,
        "longitude": 101.7782,
        "isp": "电信",
    },
    "宁夏": {
        "province": "宁夏",
        "city": "银川",
        "latitude": 38.4872,
        "longitude": 106.2309,
        "isp": "电信",
    },
    "新疆": {
        "province": "新疆",
        "city": "乌鲁木齐",
        "latitude": 43.8256,
        "longitude": 87.6168,
        "isp": "电信",
    },
    # 港澳台
    "香港": {
        "province": "香港",
        "city": "香港",
        "latitude": 22.3193,
        "longitude": 114.1694,
        "isp": "PCCW/数码通/3HK",
    },
    "澳门": {
        "province": "澳门",
        "city": "澳门",
        "latitude": 22.1987,
        "longitude": 113.5439,
        "isp": "CTM/3澳门",
    },
    "台湾": {
        "province": "台湾",
        "city": "台北",
        "latitude": 25.0330,
        "longitude": 121.5654,
        "isp": "中华电信/远传/台哥大",
    },
}

# 省份名称标准化映射（去除后缀）
PROVINCE_ALIASES = {
    "北京市": "北京", "北京": "北京",
    "上海市": "上海", "上海": "上海",
    "天津市": "天津", "天津": "天津",
    "重庆市": "重庆", "重庆": "重庆",
    "河北省": "河北", "河北": "河北",
    "山西省": "山西", "山西": "山西",
    "内蒙古自治区": "内蒙古", "内蒙古": "内蒙古",
    "辽宁省": "辽宁", "辽宁": "辽宁",
    "吉林省": "吉林", "吉林": "吉林",
    "黑龙江省": "黑龙江", "黑龙江": "黑龙江",
    "江苏省": "江苏", "江苏": "江苏",
    "浙江省": "浙江", "浙江": "浙江",
    "安徽省": "安徽", "安徽": "安徽",
    "福建省": "福建", "福建": "福建",
    "江西省": "江西", "江西": "江西",
    "山东省": "山东", "山东": "山东",
    "河南省": "河南", "河南": "河南",
    "湖北省": "湖北", "湖北": "湖北",
    "湖南省": "湖南", "湖南": "湖南",
    "广东省": "广东", "广东": "广东",
    "广西壮族自治区": "广西", "广西": "广西",
    "海南省": "海南", "海南": "海南",
    "四川省": "四川", "四川": "四川",
    "贵州省": "贵州", "贵州": "贵州",
    "云南省": "云南", "云南": "云南",
    "西藏自治区": "西藏", "西藏": "西藏",
    "陕西省": "陕西", "陕西": "陕西",
    "甘肃省": "甘肃", "甘肃": "甘肃",
    "青海省": "青海", "青海": "青海",
    "宁夏回族自治区": "宁夏", "宁夏": "宁夏",
    "新疆维吾尔自治区": "新疆", "新疆": "新疆",
    "香港特别行政区": "香港", "香港": "香港",
    "澳门特别行政区": "澳门", "澳门": "澳门",
    "台湾省": "台湾", "台湾": "台湾",
}

# 中国主要城市额外映射（用于更精确的城市定位）
CHINA_CITY_GEO = {
    "深圳": {"province": "广东", "city": "深圳", "latitude": 22.5431, "longitude": 114.0579, "isp": "电信"},
    "东莞": {"province": "广东", "city": "东莞", "latitude": 23.0208, "longitude": 113.7518, "isp": "电信"},
    "佛山": {"province": "广东", "city": "佛山", "latitude": 23.0218, "longitude": 113.1219, "isp": "电信"},
    "珠海": {"province": "广东", "city": "珠海", "latitude": 22.2710, "longitude": 113.5767, "isp": "电信"},
    "苏州": {"province": "江苏", "city": "苏州", "latitude": 31.2990, "longitude": 120.5853, "isp": "电信"},
    "无锡": {"province": "江苏", "city": "无锡", "latitude": 31.4912, "longitude": 120.3119, "isp": "电信"},
    "宁波": {"province": "浙江", "city": "宁波", "latitude": 29.8683, "longitude": 121.5440, "isp": "电信"},
    "温州": {"province": "浙江", "city": "温州", "latitude": 28.0006, "longitude": 120.6722, "isp": "电信"},
    "厦门": {"province": "福建", "city": "厦门", "latitude": 24.4798, "longitude": 118.0894, "isp": "电信"},
    "泉州": {"province": "福建", "city": "泉州", "latitude": 24.8741, "longitude": 118.6758, "isp": "电信"},
    "大连": {"province": "辽宁", "city": "大连", "latitude": 38.9140, "longitude": 121.6147, "isp": "联通"},
    "青岛": {"province": "山东", "city": "青岛", "latitude": 36.0671, "longitude": 120.3826, "isp": "联通/电信"},
    "烟台": {"province": "山东", "city": "烟台", "latitude": 37.4638, "longitude": 121.4479, "isp": "联通"},
    "洛阳": {"province": "河南", "city": "洛阳", "latitude": 34.6197, "longitude": 112.4540, "isp": "联通"},
    "东莞": {"province": "广东", "city": "东莞", "latitude": 23.0208, "longitude": 113.7518, "isp": "电信"},
    "中山": {"province": "广东", "city": "中山", "latitude": 22.5171, "longitude": 113.3926, "isp": "电信"},
    "惠州": {"province": "广东", "city": "惠州", "latitude": 23.1115, "longitude": 114.4165, "isp": "电信"},
    "常州": {"province": "江苏", "city": "常州", "latitude": 31.8106, "longitude": 119.9741, "isp": "电信"},
    "南通": {"province": "江苏", "city": "南通", "latitude": 31.9800, "longitude": 120.8943, "isp": "电信"},
    "扬州": {"province": "江苏", "city": "扬州", "latitude": 32.3932, "longitude": 119.4129, "isp": "电信"},
    "嘉兴": {"province": "浙江", "city": "嘉兴", "latitude": 30.7469, "longitude": 120.7555, "isp": "电信"},
    "绍兴": {"province": "浙江", "city": "绍兴", "latitude": 30.0000, "longitude": 120.5833, "isp": "电信"},
    "金华": {"province": "浙江", "city": "金华", "latitude": 29.0785, "longitude": 119.6494, "isp": "电信"},
    "徐州": {"province": "江苏", "city": "徐州", "latitude": 34.2618, "longitude": 117.1847, "isp": "联通/电信"},
    "保定": {"province": "河北", "city": "保定", "latitude": 38.8739, "longitude": 115.4646, "isp": "联通"},
    "唐山": {"province": "河北", "city": "唐山", "latitude": 39.6309, "longitude": 118.1802, "isp": "联通"},
    "潍坊": {"province": "山东", "city": "潍坊", "latitude": 36.7069, "longitude": 119.1619, "isp": "联通"},
    "威海": {"province": "山东", "city": "威海", "latitude": 37.5091, "longitude": 122.1164, "isp": "联通"},
    "绵阳": {"province": "四川", "city": "绵阳", "latitude": 31.4675, "longitude": 104.6796, "isp": "电信"},
    "德阳": {"province": "四川", "city": "德阳", "latitude": 31.1270, "longitude": 104.3981, "isp": "电信"},
    "宜昌": {"province": "湖北", "city": "宜昌", "latitude": 30.6918, "longitude": 111.2864, "isp": "电信"},
    "襄阳": {"province": "湖北", "city": "襄阳", "latitude": 32.0090, "longitude": 112.1228, "isp": "电信"},
    "岳阳": {"province": "湖南", "city": "岳阳", "latitude": 29.3572, "longitude": 113.1289, "isp": "电信"},
    "株洲": {"province": "湖南", "city": "株洲", "latitude": 27.8274, "longitude": 113.1340, "isp": "电信"},
    "桂林": {"province": "广西", "city": "桂林", "latitude": 25.2744, "longitude": 110.2990, "isp": "电信"},
    "柳州": {"province": "广西", "city": "柳州", "latitude": 24.3260, "longitude": 109.4115, "isp": "电信"},
    "包头": {"province": "内蒙古", "city": "包头", "latitude": 40.6571, "longitude": 109.8403, "isp": "联通"},
    "大庆": {"province": "黑龙江", "city": "大庆", "latitude": 46.5907, "longitude": 125.1040, "isp": "联通"},
    "吉林市": {"province": "吉林", "city": "吉林", "latitude": 43.8380, "longitude": 126.5496, "isp": "联通"},
}

# 中国主要 ISP 运营商
CHINA_ISPS = ["中国电信", "中国联通", "中国移动", "中国铁通", "教育网", "长城宽带", "中信网络"]

# 用于模拟归属地的 IP 哈希种子省份列表（按权重排序，模拟真实分布）
PROVINCE_WEIGHTS = [
    "广东", "广东", "广东", "北京", "北京", "上海", "上海", "浙江",
    "江苏", "江苏", "山东", "河南", "四川", "湖北", "福建", "湖南",
    "河北", "辽宁", "安徽", "陕西", "重庆", "天津", "广西", "云南",
    "江西", "山西", "贵州", "黑龙江", "吉林", "内蒙古", "新疆", "甘肃",
    "海南", "宁夏", "青海", "西藏", "香港", "台湾",
]

# ============================================================
# 全球主要国家地理信息（用于公网 IP 模拟归属地）
# ============================================================

GLOBAL_COUNTRY_GEO = [
    {"name": "美国", "name_en": "United States", "latitude": 37.09, "longitude": -95.71, "weight": 25},
    {"name": "中国", "name_en": "China", "latitude": 35.86, "longitude": 104.19, "weight": 20},
    {"name": "日本", "name_en": "Japan", "latitude": 36.20, "longitude": 138.25, "weight": 8},
    {"name": "德国", "name_en": "Germany", "latitude": 51.16, "longitude": 10.45, "weight": 6},
    {"name": "英国", "name_en": "United Kingdom", "latitude": 55.37, "longitude": -3.43, "weight": 5},
    {"name": "法国", "name_en": "France", "latitude": 46.22, "longitude": 2.21, "weight": 5},
    {"name": "巴西", "name_en": "Brazil", "latitude": -14.23, "longitude": -51.92, "weight": 5},
    {"name": "印度", "name_en": "India", "latitude": 20.59, "longitude": 78.96, "weight": 5},
    {"name": "韩国", "name_en": "Korea", "latitude": 35.90, "longitude": 127.76, "weight": 4},
    {"name": "俄罗斯", "name_en": "Russia", "latitude": 61.52, "longitude": 105.31, "weight": 4},
    {"name": "澳大利亚", "name_en": "Australia", "latitude": -25.27, "longitude": 133.77, "weight": 3},
    {"name": "加拿大", "name_en": "Canada", "latitude": 56.13, "longitude": -106.34, "weight": 3},
    {"name": "新加坡", "name_en": "Singapore", "latitude": 1.35, "longitude": 103.82, "weight": 3},
    {"name": "荷兰", "name_en": "Netherlands", "latitude": 52.13, "longitude": 5.29, "weight": 2},
    {"name": "瑞典", "name_en": "Sweden", "latitude": 60.12, "longitude": 18.64, "weight": 1},
    {"name": "意大利", "name_en": "Italy", "latitude": 41.87, "longitude": 12.56, "weight": 2},
    {"name": "西班牙", "name_en": "Spain", "latitude": 40.46, "longitude": -3.74, "weight": 2},
    {"name": "泰国", "name_en": "Thailand", "latitude": 15.87, "longitude": 100.99, "weight": 1},
    {"name": "越南", "name_en": "Vietnam", "latitude": 14.05, "longitude": 108.27, "weight": 1},
    {"name": "印度尼西亚", "name_en": "Indonesia", "latitude": -0.78, "longitude": 113.92, "weight": 1},
    {"name": "菲律宾", "name_en": "Philippines", "latitude": 12.87, "longitude": 121.77, "weight": 1},
    {"name": "马来西亚", "name_en": "Malaysia", "latitude": 4.21, "longitude": 101.97, "weight": 1},
    {"name": "土耳其", "name_en": "Turkey", "latitude": 38.96, "longitude": 35.24, "weight": 1},
    {"name": "南非", "name_en": "South Africa", "latitude": -30.55, "longitude": 22.93, "weight": 1},
    {"name": "墨西哥", "name_en": "Mexico", "latitude": 23.63, "longitude": -102.55, "weight": 1},
    {"name": "阿根廷", "name_en": "Argentina", "latitude": -38.41, "longitude": -63.61, "weight": 1},
    {"name": "波兰", "name_en": "Poland", "latitude": 51.91, "longitude": 19.14, "weight": 1},
    {"name": "乌克兰", "name_en": "Ukraine", "latitude": 48.37, "longitude": 31.16, "weight": 1},
    {"name": "以色列", "name_en": "Israel", "latitude": 31.04, "longitude": 34.85, "weight": 1},
    {"name": "阿联酋", "name_en": "United Arab Emirates", "latitude": 23.42, "longitude": 53.84, "weight": 1},
]

# 构建加权国家列表
_WEIGHTED_COUNTRIES = []
for _gc in GLOBAL_COUNTRY_GEO:
    _WEIGHTED_COUNTRIES.extend([_gc] * _gc["weight"])


def _is_private_ip(ip_str: str) -> bool:
    """检查是否为私有/内网 IP"""
    try:
        ip = ipaddress.ip_address(ip_str)
        return (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_reserved
            or ip.is_multicast
        )
    except ValueError:
        return False


def _is_china_ip(ip_str: str) -> bool:
    """判断是否为中国 IP（基于哈希模拟）"""
    try:
        ip = ipaddress.ip_address(ip_str)
        if not ip.is_global:
            return False
    except ValueError:
        return False
    # 根据哈希判断：约30%概率为中国IP
    ip_hash = int(hashlib.md5(ip_str.encode()).hexdigest(), 16)
    return ip_hash % 10 < 3


def _ip_to_global_country(ip_str: str) -> dict:
    """根据 IP 哈希分配全球国家"""
    ip_hash = int(hashlib.md5(ip_str.encode()).hexdigest(), 16)
    index = ip_hash % len(_WEIGHTED_COUNTRIES)
    return _WEIGHTED_COUNTRIES[index]


def _ip_to_province(ip_str: str) -> str:
    """
    根据 IP 地址哈希值确定模拟省份
    使用确定性哈希确保同一 IP 始终映射到同一省份
    """
    ip_hash = int(hashlib.md5(ip_str.encode()).hexdigest(), 16)
    index = ip_hash % len(PROVINCE_WEIGHTS)
    return PROVINCE_WEIGHTS[index]


def _ip_to_city(ip_str: str, province: str) -> Optional[str]:
    """
    根据 IP 地址和省份确定模拟城市
    在该省的城市列表中根据哈希选择
    """
    # 收集该省的所有城市
    cities = []
    for city_name, city_info in CHINA_CITY_GEO.items():
        if city_info["province"] == province:
            cities.append(city_name)

    # 如果没有额外城市映射，使用省会
    if not cities:
        prov_info = CHINA_PROVINCE_GEO.get(province)
        if prov_info:
            return prov_info["city"]
        return None

    # 根据哈希选择城市
    ip_hash = int(hashlib.md5((ip_str + "_city").encode()).hexdigest(), 16)
    index = ip_hash % len(cities)
    return cities[index]


def _ip_to_isp(ip_str: str) -> str:
    """根据 IP 地址哈希模拟运营商"""
    ip_hash = int(hashlib.md5((ip_str + "_isp").encode()).hexdigest(), 16)
    index = ip_hash % len(CHINA_ISPS)
    return CHINA_ISPS[index]


def _add_jitter(value: float, range_val: float = 0.5) -> float:
    """为经纬度添加微小偏移，避免多个 IP 完全重叠"""
    ip_hash = int(hashlib.md5(str(value).encode()).hexdigest(), 16)
    jitter = (ip_hash % 1000) / 1000.0 * range_val - range_val / 2
    return round(value + jitter, 4)


def query_ip_geo(ip_str: str) -> Dict[str, Any]:
    """
    查询 IP 归属地信息

    Args:
        ip_str: IP 地址字符串

    Returns:
        dict: {
            "ip": str,
            "country": str,
            "province": str,
            "city": str,
            "isp": str,
            "latitude": float,
            "longitude": float,
            "is_private": bool,
        }
    """
    result = {
        "ip": ip_str,
        "country": "",
        "province": "",
        "city": "",
        "isp": "",
        "latitude": None,
        "longitude": None,
        "is_private": False,
    }

    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        result["country"] = "无效IP"
        return result

    # 1. 检查私有/内网 IP
    if _is_private_ip(ip_str):
        result["is_private"] = True
        result["country"] = "中国"
        result["province"] = "内网"
        result["city"] = "内网"
        result["isp"] = "内网地址"
        result["latitude"] = 0.0
        result["longitude"] = 0.0
        return result

    # 2. 检查回环地址
    if ip.is_loopback:
        result["country"] = "中国"
        result["province"] = "本地"
        result["city"] = "本地"
        result["isp"] = "回环地址"
        result["latitude"] = 0.0
        result["longitude"] = 0.0
        return result

    # 3. 对公网 IP 进行模拟归属地查询
    if _is_china_ip(ip_str):
        result["country"] = "中国"

        # 确定省份
        province = _ip_to_province(ip_str)
        result["province"] = province

        # 确定城市
        city = _ip_to_city(ip_str, province)
        result["city"] = city or province

        # 确定运营商
        result["isp"] = _ip_to_isp(ip_str)

        # 获取经纬度
        geo_info = None

        # 先查城市级
        if city and city in CHINA_CITY_GEO:
            geo_info = CHINA_CITY_GEO[city]

        # 再查省份级
        if not geo_info and province in CHINA_PROVINCE_GEO:
            geo_info = CHINA_PROVINCE_GEO[province]

        if geo_info:
            result["latitude"] = _add_jitter(geo_info["latitude"], 0.3)
            result["longitude"] = _add_jitter(geo_info["longitude"], 0.3)
        else:
            # 默认使用北京坐标
            result["latitude"] = _add_jitter(39.9042, 0.3)
            result["longitude"] = _add_jitter(116.4074, 0.3)
    else:
        # 非中国IP：分配到全球国家
        country_info = _ip_to_global_country(ip_str)
        result["country"] = country_info["name"]
        result["province"] = country_info["name"]
        result["city"] = ""
        result["isp"] = ""
        result["latitude"] = _add_jitter(country_info["latitude"], 2.0)
        result["longitude"] = _add_jitter(country_info["longitude"], 2.0)

    return result


def batch_query_ip_geo(ip_list: List[str]) -> List[Dict[str, Any]]:
    """
    批量查询 IP 归属地

    Args:
        ip_list: IP 地址列表

    Returns:
        list: 归属地信息列表
    """
    results = []
    for ip_str in ip_list:
        results.append(query_ip_geo(ip_str))
    return results


def normalize_province_name(name: str) -> str:
    """
    标准化省份名称，去除"省"、"市"、"自治区"等后缀

    Args:
        name: 原始省份名称

    Returns:
        str: 标准化后的省份名称
    """
    if not name:
        return ""
    # 去除常见后缀
    for suffix in ["省", "市", "自治区", "特别行政区", "壮族", "维吾尔", "回族"]:
        name = name.replace(suffix, "")
    # 查找别名映射
    return PROVINCE_ALIASES.get(name, name)


def get_all_provinces() -> List[str]:
    """获取所有支持的省份列表"""
    return list(CHINA_PROVINCE_GEO.keys())


def get_province_geo(province_name: str) -> Optional[Dict[str, Any]]:
    """
    获取省份的地理信息

    Args:
        province_name: 省份名称

    Returns:
        dict or None: 省份地理信息
    """
    normalized = normalize_province_name(province_name)
    return CHINA_PROVINCE_GEO.get(normalized)
