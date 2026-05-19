"""
GateKeeper - AI 配置管理器
管理 AI 提供商的配置和调用，提供便捷的配置操作函数
"""

import json
from typing import Dict, Any, Optional, List

from config.logging_config import get_logger
from ai_engine.llm_provider import (
    LLMProvider,
    LLMProviderConfig,
    PROVIDER_TEMPLATES,
    llm_provider,
)

logger = get_logger("ai_config")


# ============================================================
# 配置验证
# ============================================================

def validate_provider_config(config_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    验证提供商配置数据

    Args:
        config_data: 待验证的配置字典

    Returns:
        {"valid": True/False, "errors": [...]}
    """
    errors = []

    # 必填字段检查
    required_fields = ["provider_type", "name"]
    for field_name in required_fields:
        if not config_data.get(field_name):
            errors.append("缺少必填字段: {}".format(field_name))

    provider_type = config_data.get("provider_type", "")

    # 检查提供商类型是否在模板中（openai_compatible 除外，它允许自定义）
    if provider_type and provider_type != "openai_compatible":
        if provider_type not in PROVIDER_TEMPLATES:
            errors.append("不支持的提供商类型: {}".format(provider_type))

    # API Base URL 检查（openai_compatible 必须提供）
    if provider_type == "openai_compatible" and not config_data.get("api_base"):
        errors.append("OpenAI 兼容模式必须提供 API Base URL")

    # API Key 检查（启用时必须提供）
    if config_data.get("enabled") and not config_data.get("api_key"):
        errors.append("启用提供商必须提供 API Key")

    # 模型名称检查（启用时必须提供）
    if config_data.get("enabled") and not config_data.get("model"):
        errors.append("启用提供商必须指定默认模型")

    # 温度范围检查
    temperature = config_data.get("temperature", 0.7)
    if not isinstance(temperature, (int, float)) or temperature < 0 or temperature > 2.0:
        errors.append("温度值必须在 0.0 ~ 2.0 之间")

    # max_tokens 检查
    max_tokens = config_data.get("max_tokens", 4096)
    if not isinstance(max_tokens, int) or max_tokens < 1 or max_tokens > 65536:
        errors.append("max_tokens 必须是 1 ~ 65536 之间的整数")

    return {
        "valid": len(errors) == 0,
        "errors": errors,
    }


def validate_api_key(provider_type: str, api_key: str) -> Dict[str, Any]:
    """
    验证 API Key 格式

    Args:
        provider_type: 提供商类型
        api_key: API Key 值

    Returns:
        {"valid": True/False, "message": "..."}
    """
    if not api_key or not api_key.strip():
        return {"valid": False, "message": "API Key 不能为空"}

    api_key = api_key.strip()

    # 各提供商的 API Key 格式检查
    if provider_type == "qwen":
        # 阿里云 DashScope Key: sk- 开头，长度通常 32+
        if not api_key.startswith("sk-"):
            return {"valid": False, "message": "通义千问 API Key 应以 'sk-' 开头"}

    elif provider_type == "zhipu":
        # 智谱 API Key: 通常为 32 位十六进制字符串
        if len(api_key) < 16:
            return {"valid": False, "message": "智谱 GLM API Key 长度不足"}

    elif provider_type == "baidu":
        # 百度 API Key: 通常为 24 位字符串
        if len(api_key) < 16:
            return {"valid": False, "message": "百度文心 API Key 长度不足"}

    elif provider_type == "spark":
        # 讯飞星火 API Key: 通常为特定格式
        if len(api_key) < 16:
            return {"valid": False, "message": "讯飞星火 API Key 长度不足"}

    elif provider_type == "deepseek":
        # DeepSeek API Key: sk- 开头
        if not api_key.startswith("sk-"):
            return {"valid": False, "message": "DeepSeek API Key 应以 'sk-' 开头"}

    elif provider_type == "moonshot":
        # Moonshot API Key: 通常为特定格式
        if len(api_key) < 16:
            return {"valid": False, "message": "Moonshot API Key 长度不足"}

    elif provider_type == "siliconflow":
        # 硅基流动 API Key: sk- 开头
        if not api_key.startswith("sk-"):
            return {"valid": False, "message": "硅基流动 API Key 应以 'sk-' 开头"}

    # openai_compatible 不做格式校验

    return {"valid": True, "message": "API Key 格式校验通过"}


# ============================================================
# 配置获取函数
# ============================================================

def get_ai_config() -> Dict[str, Any]:
    """
    获取完整的 AI 配置信息

    Returns:
        {
            "providers": [...],       # 已配置的提供商列表
            "default_provider": "...", # 默认提供商类型
            "templates": {...},        # 可用的提供商模板
        }
    """
    llm_provider._ensure_loaded()
    return {
        "providers": llm_provider.list_providers(),
        "default_provider": llm_provider._default_provider,
        "templates": llm_provider.list_templates(),
    }


def get_provider_config(provider_type: str) -> Optional[Dict[str, Any]]:
    """
    获取指定提供商的配置

    Args:
        provider_type: 提供商类型标识

    Returns:
        提供商配置字典（不含 API Key），或 None
    """
    config = llm_provider.get_provider(provider_type)
    if not config:
        return None

    info = config.to_dict()
    # 隐藏 API Key
    if info.get("api_key"):
        info["api_key_masked"] = info["api_key"][:8] + "****"
    else:
        info["api_key_masked"] = ""
    info.pop("api_key", None)
    return info


def get_provider_template(provider_type: str) -> Optional[Dict[str, Any]]:
    """
    获取指定提供商的模板信息

    Args:
        provider_type: 提供商类型标识

    Returns:
        提供商模板字典，或 None
    """
    return PROVIDER_TEMPLATES.get(provider_type)


def get_default_provider() -> Optional[Dict[str, Any]]:
    """
    获取默认提供商配置

    Returns:
        默认提供商配置字典，或 None
    """
    config = llm_provider.get_default_provider()
    if not config:
        return None

    info = config.to_dict()
    if info.get("api_key"):
        info["api_key_masked"] = info["api_key"][:8] + "****"
    else:
        info["api_key_masked"] = ""
    info.pop("api_key", None)
    return info


# ============================================================
# 配置保存函数
# ============================================================

def save_ai_config(config_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    保存 AI 提供商配置

    Args:
        config_data: 配置数据字典，包含:
            - provider_type: 提供商类型（必填）
            - name: 提供商名称
            - api_key: API Key
            - api_base: API Base URL
            - model: 默认模型
            - max_tokens: 最大 token
            - temperature: 温度
            - enabled: 是否启用
            - is_default: 是否为默认

    Returns:
        {"success": True/False, "message": "...", "config": {...}}
    """
    # 验证配置
    validation = validate_provider_config(config_data)
    if not validation["valid"]:
        return {
            "success": False,
            "message": "配置验证失败: {}".format("; ".join(validation["errors"])),
        }

    provider_type = config_data["provider_type"]

    # 如果提供了 API Key，验证格式
    if config_data.get("api_key"):
        key_validation = validate_api_key(provider_type, config_data["api_key"])
        if not key_validation["valid"]:
            return {
                "success": False,
                "message": "API Key 验证失败: {}".format(key_validation["message"]),
            }

    # 获取已有配置（用于合并）
    existing = llm_provider.get_provider(provider_type)
    if existing:
        # 合并：已有配置中未提供的字段保持不变
        existing_data = existing.to_dict()
        for key, value in config_data.items():
            existing_data[key] = value
        config_data = existing_data

    # 构建 LLMProviderConfig
    try:
        provider_config = LLMProviderConfig.from_dict(config_data)

        # 如果是 openai_compatible 且未指定 api_base，从模板获取
        if provider_type != "openai_compatible" and not provider_config.api_base:
            template = PROVIDER_TEMPLATES.get(provider_type)
            if template:
                provider_config.api_base = template["api_base"]

        llm_provider.save_config(provider_config)

        logger.info("AI 提供商配置已保存: {} ({})".format(
            provider_config.name, provider_type
        ))

        return {
            "success": True,
            "message": "配置保存成功",
            "config": get_provider_config(provider_type),
        }

    except Exception as e:
        logger.error("保存 AI 配置失败: {}".format(e))
        return {
            "success": False,
            "message": "保存失败: {}".format(str(e)),
        }


def delete_ai_config(provider_type: str) -> Dict[str, Any]:
    """
    删除 AI 提供商配置

    Args:
        provider_type: 提供商类型标识

    Returns:
        {"success": True/False, "message": "..."}
    """
    try:
        llm_provider.delete_config(provider_type)
        return {
            "success": True,
            "message": "提供商 '{}' 配置已删除".format(provider_type),
        }
    except Exception as e:
        logger.error("删除 AI 配置失败: {}".format(e))
        return {
            "success": False,
            "message": "删除失败: {}".format(str(e)),
        }


def set_default_ai_provider(provider_type: str) -> Dict[str, Any]:
    """
    设置默认 AI 提供商

    Args:
        provider_type: 提供商类型标识

    Returns:
        {"success": True/False, "message": "..."}
    """
    try:
        llm_provider.set_default_provider(provider_type)
        return {
            "success": True,
            "message": "默认提供商已设置为 '{}'".format(provider_type),
        }
    except ValueError as e:
        return {
            "success": False,
            "message": str(e),
        }
    except Exception as e:
        logger.error("设置默认 AI 提供商失败: {}".format(e))
        return {
            "success": False,
            "message": "设置失败: {}".format(str(e)),
        }


# ============================================================
# LLM 调用便捷函数
# ============================================================

def chat(
    messages: List[Dict],
    provider_type: str = None,
    model: str = None,
    temperature: float = None,
    max_tokens: int = None,
) -> Dict[str, Any]:
    """
    调用 LLM 的便捷函数

    Args:
        messages: 消息列表 [{"role": "user", "content": "..."}]
        provider_type: 提供商类型（不指定则使用默认）
        model: 模型名称（不指定则使用提供商默认）
        temperature: 温度
        max_tokens: 最大 token

    Returns:
        {"content": "...", "usage": {...}, "model": "..."}
    """
    return llm_provider.chat(
        messages=messages,
        provider_type=provider_type,
        model=model,
        temperature=temperature,
        max_tokens=max_tokens,
    )


def test_provider_connection(provider_type: str) -> Dict[str, Any]:
    """
    测试提供商连接的便捷函数

    Args:
        provider_type: 提供商类型标识

    Returns:
        {"success": True/False, "message": "...", "latency_ms": N}
    """
    return llm_provider.test_connection(provider_type)


# ============================================================
# 批量配置操作
# ============================================================

def import_provider_configs(configs: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    批量导入提供商配置

    Args:
        configs: 配置列表，每项为一个提供商配置字典

    Returns:
        {"success": N, "failed": N, "results": [...]}
    """
    success_count = 0
    failed_count = 0
    results = []

    for config_data in configs:
        result = save_ai_config(config_data)
        results.append({
            "provider_type": config_data.get("provider_type", "unknown"),
            "success": result["success"],
            "message": result["message"],
        })
        if result["success"]:
            success_count += 1
        else:
            failed_count += 1

    logger.info(
        "批量导入 AI 配置完成: 成功={}, 失败={}".format(success_count, failed_count)
    )

    return {
        "success": success_count,
        "failed": failed_count,
        "results": results,
    }


def export_provider_configs() -> Dict[str, Any]:
    """
    导出所有提供商配置（不含 API Key）

    Returns:
        {"providers": [...], "default_provider": "..."}
    """
    return {
        "providers": llm_provider.list_providers(),
        "default_provider": llm_provider._default_provider,
    }


def reset_to_templates() -> Dict[str, Any]:
    """
    重置所有配置为模板默认值（清除所有已保存的提供商配置）

    Returns:
        {"success": True, "message": "..."}
    """
    try:
        llm_provider._ensure_loaded()
        provider_types = list(llm_provider._providers.keys())

        for pt in provider_types:
            llm_provider.delete_config(pt)

        logger.info("AI 提供商配置已重置")
        return {
            "success": True,
            "message": "所有提供商配置已重置",
        }
    except Exception as e:
        logger.error("重置 AI 配置失败: {}".format(e))
        return {
            "success": False,
            "message": "重置失败: {}".format(str(e)),
        }


# ============================================================
# 配置状态检查
# ============================================================

def get_config_status() -> Dict[str, Any]:
    """
    获取 AI 配置状态概览

    Returns:
        {
            "configured": bool,          # 是否有已配置的提供商
            "enabled_count": int,        # 已启用的提供商数量
            "has_default": bool,         # 是否设置了默认提供商
            "default_provider": str,     # 默认提供商名称
            "providers": [...],          # 提供商概览列表
        }
    """
    llm_provider._ensure_loaded()

    providers = llm_provider.list_providers()
    enabled_count = sum(1 for p in providers if p.get("enabled"))
    has_default = llm_provider._default_provider is not None
    default_name = ""
    if has_default:
        default_config = llm_provider.get_provider(llm_provider._default_provider)
        if default_config:
            default_name = default_config.name

    return {
        "configured": len(providers) > 0,
        "enabled_count": enabled_count,
        "has_default": has_default,
        "default_provider": default_name,
        "providers": [
            {
                "provider_type": p.get("provider_type"),
                "name": p.get("name"),
                "enabled": p.get("enabled"),
                "is_default": p.get("is_default"),
                "model": p.get("model"),
                "has_api_key": bool(p.get("api_key_masked")),
            }
            for p in providers
        ],
    }
