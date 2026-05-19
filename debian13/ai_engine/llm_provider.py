"""
GateKeeper - LLM 提供商统一接口
支持国内主流 AI 系统的统一调用
"""

import json
import os
try:
    import requests
except ImportError:
    requests = None
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field

from config.logging_config import get_logger

logger = get_logger("llm_provider")

# 加密工具
try:
    from utils.crypto import encrypt_data, decrypt_data
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False
    logger.warning("加密模块不可用，API Key 将以明文存储")


# ============================================================
# 提供商配置数据类
# ============================================================

@dataclass
class LLMProviderConfig:
    """AI 提供商配置"""
    name: str = ""                    # 提供商名称
    provider_type: str = ""           # 提供商类型标识
    api_key: str = ""                 # API Key
    api_base: str = ""                # API Base URL
    model: str = ""                   # 默认模型
    max_tokens: int = 4096            # 最大 token
    temperature: float = 0.7          # 温度
    enabled: bool = False             # 是否启用
    is_default: bool = False          # 是否为默认提供商

    def to_dict(self) -> Dict[str, Any]:
        """序列化为字典"""
        return {
            "name": self.name,
            "provider_type": self.provider_type,
            "api_key": self.api_key,
            "api_base": self.api_base,
            "model": self.model,
            "max_tokens": self.max_tokens,
            "temperature": self.temperature,
            "enabled": self.enabled,
            "is_default": self.is_default,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "LLMProviderConfig":
        """从字典反序列化"""
        return cls(
            name=data.get("name", ""),
            provider_type=data.get("provider_type", ""),
            api_key=data.get("api_key", ""),
            api_base=data.get("api_base", ""),
            model=data.get("model", ""),
            max_tokens=data.get("max_tokens", 4096),
            temperature=data.get("temperature", 0.7),
            enabled=data.get("enabled", False),
            is_default=data.get("is_default", False),
        )


# ============================================================
# 预定义的提供商模板
# ============================================================

PROVIDER_TEMPLATES = {
    "qwen": {
        "name": "通义千问 (阿里云)",
        "provider_type": "qwen",
        "api_base": "https://dashscope.aliyuncs.com/compatible-mode/v1",
        "models": ["qwen-turbo", "qwen-plus", "qwen-max", "qwen-long"],
        "max_tokens": 8192,
    },
    "zhipu": {
        "name": "智谱 GLM",
        "provider_type": "zhipu",
        "api_base": "https://open.bigmodel.cn/api/paas/v4",
        "models": ["glm-4-flash", "glm-4-air", "glm-4-plus", "glm-4-long"],
        "max_tokens": 8192,
    },
    "baidu": {
        "name": "百度文心一言",
        "provider_type": "baidu",
        "api_base": "https://aip.baidubce.com/rpc/2.0/ai_custom/v1",
        "models": ["ernie-speed-128k", "ernie-lite-8k", "ernie-4.0-8k"],
        "max_tokens": 4096,
    },
    "spark": {
        "name": "讯飞星火",
        "provider_type": "spark",
        "api_base": "https://spark-api-open.xf-yun.com/v1",
        "models": ["generalv3.5", "generalv3", "4.0Ultra"],
        "max_tokens": 4096,
    },
    "deepseek": {
        "name": "DeepSeek",
        "provider_type": "deepseek",
        "api_base": "https://api.deepseek.com/v1",
        "models": ["deepseek-chat", "deepseek-coder", "deepseek-reasoner"],
        "max_tokens": 8192,
    },
    "moonshot": {
        "name": "月之暗面 Kimi",
        "provider_type": "moonshot",
        "api_base": "https://api.moonshot.cn/v1",
        "models": ["moonshot-v1-8k", "moonshot-v1-32k", "moonshot-v1-128k"],
        "max_tokens": 4096,
    },
    "siliconflow": {
        "name": "硅基流动",
        "provider_type": "siliconflow",
        "api_base": "https://api.siliconflow.cn/v1",
        "models": ["Qwen/Qwen2.5-7B-Instruct", "deepseek-ai/DeepSeek-V2.5", "THUDM/glm-4-9b-chat"],
        "max_tokens": 4096,
    },
    "openai_compatible": {
        "name": "OpenAI 兼容",
        "provider_type": "openai_compatible",
        "api_base": "",
        "models": [],
        "max_tokens": 4096,
    },
}


# ============================================================
# LLM 提供商统一调用接口
# ============================================================

class LLMProvider:
    """
    统一的 LLM 调用接口
    支持国内主流 AI 提供商的统一调用和配置管理
    """

    # 请求超时时间（秒）
    REQUEST_TIMEOUT = 30

    # 测试连接时发送的消息
    TEST_MESSAGE = '你好，请回复"连接成功"四个字。'

    def __init__(self):
        self._providers: Dict[str, LLMProviderConfig] = {}
        self._default_provider: Optional[str] = None
        self._initialized = False

    # --------------------------------------------------------
    # 配置加载与持久化
    # --------------------------------------------------------

    def _is_encrypted(self, value: str) -> bool:
        """检查值是否已加密（加密后的值为 Base64 编码，长度较长且不含常见明文字符）"""
        if not value or len(value) < 20:
            return False
        # 加密后的值是 Base64 编码的，尝试 base64 解码来判断
        import base64
        try:
            decoded = base64.b64decode(value)
            # 加密后的数据至少包含 12 字节 nonce + 16 字节 tag + 密文 = 28+ 字节
            return len(decoded) >= 28
        except Exception:
            return False

    def _encrypt_api_key(self, api_key: str) -> str:
        """加密 API Key"""
        if not api_key:
            return api_key
        if not HAS_CRYPTO:
            raise RuntimeError("加密模块不可用，无法安全存储 API Key。请安装 cryptography 库。")
        try:
            return encrypt_data(api_key)
        except Exception as e:
            logger.warning("加密 API Key 失败，将使用明文存储: {}".format(e))
            return api_key

    def _decrypt_api_key(self, api_key: str) -> str:
        """解密 API Key，如果未加密则原样返回"""
        if not api_key or not HAS_CRYPTO:
            return api_key
        if not self._is_encrypted(api_key):
            return api_key
        try:
            return decrypt_data(api_key)
        except Exception as e:
            logger.warning("解密 API Key 失败: {}".format(e))
            return api_key

    def load_config(self):
        """
        从数据库加载 AI 提供商配置
        读取 SystemConfig 表中 category='ai_provider' 的记录
        """
        try:
            from core.database import db_manager
            from core.models import SystemConfig

            with db_manager.get_session() as session:
                configs = (
                    session.query(SystemConfig)
                    .filter_by(category="ai_provider")
                    .all()
                )

                self._providers.clear()
                self._default_provider = None

                for cfg in configs:
                    try:
                        config_data = cfg.get_typed_value()
                        if isinstance(config_data, dict):
                            provider_config = LLMProviderConfig.from_dict(config_data)
                            # 解密 API Key
                            provider_config.api_key = self._decrypt_api_key(provider_config.api_key)
                            # 迁移: 如果 API Key 未加密，自动加密并回写数据库
                            if provider_config.api_key and HAS_CRYPTO and not self._is_encrypted(config_data.get("api_key", "")):
                                try:
                                    encrypted_key = self._encrypt_api_key(provider_config.api_key)
                                    config_data["api_key"] = encrypted_key
                                    cfg.value = json.dumps(config_data, ensure_ascii=False)
                                    logger.info("已迁移加密 API Key: {}".format(provider_config.provider_type))
                                except Exception as migrate_err:
                                    logger.warning("迁移加密 API Key 失败 [{}]: {}".format(provider_config.provider_type, migrate_err))
                            self._providers[provider_config.provider_type] = provider_config
                            if provider_config.is_default:
                                self._default_provider = provider_config.provider_type
                    except Exception as e:
                        logger.warning(
                            "加载提供商配置失败 [key={}]: {}".format(cfg.key, e)
                        )

                self._initialized = True
                logger.info(
                    "AI 提供商配置加载完成: 共{}个提供商, 默认: {}".format(
                        len(self._providers),
                        self._default_provider or "未设置",
                    )
                )

        except Exception as e:
            logger.error("加载 AI 提供商配置失败: {}".format(e))
            self._initialized = False

    def _ensure_loaded(self):
        """确保配置已加载"""
        if not self._initialized:
            self.load_config()

    def save_config(self, config: LLMProviderConfig):
        """
        保存提供商配置到数据库

        Args:
            config: 提供商配置对象
        """
        try:
            from core.database import db_manager
            from core.models import SystemConfig

            provider_type = config.provider_type
            config_key = "provider_{}".format(provider_type)
            # 加密 API Key 后再保存到数据库
            save_dict = config.to_dict()
            if save_dict.get("api_key"):
                save_dict["api_key"] = self._encrypt_api_key(save_dict["api_key"])
            config_value = json.dumps(save_dict, ensure_ascii=False)

            with db_manager.get_session() as session:
                # 查找已有配置
                existing = (
                    session.query(SystemConfig)
                    .filter_by(category="ai_provider", key=config_key)
                    .first()
                )

                if existing:
                    existing.value = config_value
                    existing.description = "AI 提供商配置: {}".format(config.name)
                else:
                    new_config = SystemConfig(
                        category="ai_provider",
                        key=config_key,
                        value=config_value,
                        value_type="json",
                        description="AI 提供商配置: {}".format(config.name),
                    )
                    session.add(new_config)

            # 更新内存缓存
            self._providers[provider_type] = config

            # 如果设为默认，需要清除其他提供商的默认标记
            if config.is_default:
                self._default_provider = provider_type
                for pt, pc in self._providers.items():
                    if pt != provider_type and pc.is_default:
                        pc.is_default = False
                        self._persist_provider(pc)

            logger.info("AI 提供商配置已保存: {} ({})".format(config.name, provider_type))

        except Exception as e:
            logger.error("保存 AI 提供商配置失败: {}".format(e))
            raise

    def _persist_provider(self, config: LLMProviderConfig):
        """将单个提供商配置持久化到数据库（内部方法）"""
        try:
            from core.database import db_manager
            from core.models import SystemConfig

            config_key = "provider_{}".format(config.provider_type)
            # 加密 API Key 后再保存到数据库
            save_dict = config.to_dict()
            if save_dict.get("api_key"):
                save_dict["api_key"] = self._encrypt_api_key(save_dict["api_key"])
            config_value = json.dumps(save_dict, ensure_ascii=False)

            with db_manager.get_session() as session:
                existing = (
                    session.query(SystemConfig)
                    .filter_by(category="ai_provider", key=config_key)
                    .first()
                )
                if existing:
                    existing.value = config_value
                else:
                    new_config = SystemConfig(
                        category="ai_provider",
                        key=config_key,
                        value=config_value,
                        value_type="json",
                        description="AI 提供商配置: {}".format(config.name),
                    )
                    session.add(new_config)
        except Exception as e:
            logger.error("持久化提供商配置失败 [{}]: {}".format(config.provider_type, e))

    def delete_config(self, provider_type: str):
        """
        删除提供商配置

        Args:
            provider_type: 提供商类型标识
        """
        try:
            from core.database import db_manager
            from core.models import SystemConfig

            config_key = "provider_{}".format(provider_type)

            with db_manager.get_session() as session:
                existing = (
                    session.query(SystemConfig)
                    .filter_by(category="ai_provider", key=config_key)
                    .first()
                )
                if existing:
                    session.delete(existing)

            # 清除内存缓存
            if provider_type in self._providers:
                del self._providers[provider_type]

            # 如果删除的是默认提供商，清除默认标记
            if self._default_provider == provider_type:
                self._default_provider = None

            logger.info("AI 提供商配置已删除: {}".format(provider_type))

        except Exception as e:
            logger.error("删除 AI 提供商配置失败: {}".format(e))
            raise

    # --------------------------------------------------------
    # 默认提供商管理
    # --------------------------------------------------------

    def get_default_provider(self) -> Optional[LLMProviderConfig]:
        """
        获取默认提供商

        Returns:
            默认提供商配置，或 None
        """
        self._ensure_loaded()
        if self._default_provider and self._default_provider in self._providers:
            return self._providers[self._default_provider]

        # 如果未设置默认，返回第一个已启用的提供商
        for config in self._providers.values():
            if config.enabled:
                return config
        return None

    def set_default_provider(self, provider_type: str):
        """
        设置默认提供商

        Args:
            provider_type: 提供商类型标识
        """
        self._ensure_loaded()

        if provider_type not in self._providers:
            raise ValueError("提供商 '{}' 未配置".format(provider_type))

        # 清除所有提供商的默认标记
        for pt, pc in self._providers.items():
            if pc.is_default:
                pc.is_default = False
                self._persist_provider(pc)

        # 设置新的默认提供商
        self._providers[provider_type].is_default = True
        self._persist_provider(self._providers[provider_type])
        self._default_provider = provider_type

        logger.info("默认 AI 提供商已设置为: {}".format(provider_type))

    # --------------------------------------------------------
    # LLM 调用
    # --------------------------------------------------------

    def chat(
        self,
        messages: List[Dict],
        provider_type: str = None,
        model: str = None,
        temperature: float = None,
        max_tokens: int = None,
        stream: bool = False,
    ) -> Dict[str, Any]:
        """
        调用 LLM

        Args:
            messages: 消息列表 [{"role": "user", "content": "..."}]
            provider_type: 提供商类型（不指定则使用默认）
            model: 模型名称（不指定则使用提供商默认）
            temperature: 温度
            max_tokens: 最大 token
            stream: 是否流式输出

        Returns:
            {"content": "...", "usage": {"prompt_tokens": N, "completion_tokens": N}, "model": "..."}
        """
        self._ensure_loaded()

        # 确定使用哪个提供商
        if provider_type:
            config = self._providers.get(provider_type)
            if not config:
                raise ValueError("提供商 '{}' 未配置".format(provider_type))
        else:
            config = self.get_default_provider()
            if not config:
                raise ValueError("未设置默认 AI 提供商，请先配置")

        if not config.enabled:
            raise ValueError("提供商 '{}' 已禁用".format(config.name))

        if not config.api_key:
            raise ValueError("提供商 '{}' 未设置 API Key".format(config.name))

        # 合并参数
        use_model = model or config.model
        use_temperature = temperature if temperature is not None else config.temperature
        use_max_tokens = max_tokens or config.max_tokens

        if not use_model:
            raise ValueError("未指定模型名称，请设置提供商默认模型或调用时指定 model 参数")

        # 根据提供商类型分发调用
        kwargs = {
            "messages": messages,
            "model": use_model,
            "temperature": use_temperature,
            "max_tokens": use_max_tokens,
            "stream": stream,
        }

        logger.info(
            "调用 LLM: provider={}, model={}, messages={}, stream={}".format(
                config.provider_type, use_model, len(messages), stream
            )
        )

        try:
            if config.provider_type == "baidu":
                result = self._call_baidu(config, **kwargs)
            elif config.provider_type == "spark":
                result = self._call_spark(config, **kwargs)
            else:
                # 通义千问、智谱GLM、DeepSeek、Moonshot、硅基流动、OpenAI兼容
                # 均使用 OpenAI 兼容格式
                result = self._call_openai_compatible(config, **kwargs)

            logger.info(
                "LLM 调用成功: provider={}, model={}, prompt_tokens={}, completion_tokens={}".format(
                    config.provider_type,
                    result.get("model", use_model),
                    result.get("usage", {}).get("prompt_tokens", 0),
                    result.get("usage", {}).get("completion_tokens", 0),
                )
            )
            return result

        except AttributeError:
            if requests is None:
                raise RuntimeError("requests 库未安装，无法调用 LLM API")
            raise
        except requests.exceptions.Timeout:
            logger.error("LLM 调用超时: provider={}, model={}".format(config.provider_type, use_model))
            raise
        except requests.exceptions.ConnectionError as e:
            logger.error("LLM 连接失败: provider={}, error={}".format(config.provider_type, e))
            raise
        except Exception as e:
            logger.error("LLM 调用异常: provider={}, model={}, error={}".format(
                config.provider_type, use_model, e
            ))
            raise

    # --------------------------------------------------------
    # 连接测试
    # --------------------------------------------------------

    def test_connection(self, provider_type: str) -> Dict[str, Any]:
        """
        测试提供商连接
        发送一条简单消息验证 API Key 是否有效

        Args:
            provider_type: 提供商类型标识

        Returns:
            {"success": True/False, "message": "...", "latency_ms": N, "model": "..."}
        """
        self._ensure_loaded()

        config = self._providers.get(provider_type)
        if not config:
            return {
                "success": False,
                "message": "提供商 '{}' 未配置".format(provider_type),
                "latency_ms": 0,
            }

        if not config.api_key:
            return {
                "success": False,
                "message": "提供商 '{}' 未设置 API Key".format(config.name),
                "latency_ms": 0,
            }

        if not config.model:
            return {
                "success": False,
                "message": "提供商 '{}' 未设置默认模型".format(config.name),
                "latency_ms": 0,
            }

        import time
        start_time = time.time()

        try:
            messages = [{"role": "user", "content": self.TEST_MESSAGE}]
            result = self.chat(
                messages=messages,
                provider_type=provider_type,
                max_tokens=50,
            )
            elapsed_ms = int((time.time() - start_time) * 1000)

            return {
                "success": True,
                "message": "连接成功",
                "latency_ms": elapsed_ms,
                "model": result.get("model", config.model),
                "response_preview": result.get("content", "")[:100],
            }

        except Exception as e:
            elapsed_ms = int((time.time() - start_time) * 1000)
            error_msg = str(e)
            # 截断过长的错误信息
            if len(error_msg) > 500:
                error_msg = error_msg[:500] + "..."

            return {
                "success": False,
                "message": "连接失败: {}".format(error_msg),
                "latency_ms": elapsed_ms,
            }

    # --------------------------------------------------------
    # 提供商列表
    # --------------------------------------------------------

    def list_providers(self) -> List[Dict]:
        """
        列出所有已配置的提供商

        Returns:
            提供商配置列表（不包含 API Key）
        """
        self._ensure_loaded()
        result = []
        for provider_type, config in self._providers.items():
            info = config.to_dict()
            # 隐藏 API Key，只显示前8位
            if info.get("api_key"):
                info["api_key_masked"] = info["api_key"][:8] + "****"
            else:
                info["api_key_masked"] = ""
            info.pop("api_key", None)
            result.append(info)
        return result

    def list_templates(self) -> Dict[str, Dict]:
        """
        列出所有可用的提供商模板

        Returns:
            提供商模板字典
        """
        return PROVIDER_TEMPLATES

    def get_provider(self, provider_type: str) -> Optional[LLMProviderConfig]:
        """
        获取指定提供商的配置

        Args:
            provider_type: 提供商类型标识

        Returns:
            提供商配置，或 None
        """
        self._ensure_loaded()
        return self._providers.get(provider_type)

    # --------------------------------------------------------
    # 内部 API 调用方法
    # --------------------------------------------------------

    def _call_openai_compatible(
        self,
        config: LLMProviderConfig,
        messages: List[Dict],
        model: str,
        temperature: float,
        max_tokens: int,
        stream: bool = False,
    ) -> Dict[str, Any]:
        """
        调用 OpenAI 兼容 API
        适用于: 通义千问、智谱GLM、DeepSeek、Moonshot、硅基流动、OpenAI兼容

        POST {api_base}/chat/completions
        Headers: Authorization: Bearer {api_key}
        Body: {"model": ..., "messages": ..., "temperature": ..., "max_tokens": ...}
        """
        url = "{}/chat/completions".format(config.api_base.rstrip("/"))

        headers = {
            "Content-Type": "application/json",
            "Authorization": "Bearer {}".format(config.api_key),
        }

        payload = {
            "model": model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
        }

        if stream:
            payload["stream"] = True

        response = requests.post(
            url,
            headers=headers,
            json=payload,
            timeout=self.REQUEST_TIMEOUT,
        )

        if response.status_code != 200:
            error_detail = ""
            try:
                error_data = response.json()
                error_detail = error_data.get("error", {}).get("message", "")
                if not error_detail:
                    error_detail = json.dumps(error_data, ensure_ascii=False)
            except Exception:
                error_detail = response.text[:500] if response.text else "未知错误"

            raise RuntimeError(
                "API 请求失败 [{}]: HTTP {}, {}".format(
                    config.name, response.status_code, error_detail
                )
            )

        result = response.json()

        # 解析响应
        content = ""
        usage = {}
        response_model = model

        if "choices" in result and len(result["choices"]) > 0:
            choice = result["choices"][0]
            message = choice.get("message", {})
            content = message.get("content", "")

        if "usage" in result:
            usage = {
                "prompt_tokens": result["usage"].get("prompt_tokens", 0),
                "completion_tokens": result["usage"].get("completion_tokens", 0),
                "total_tokens": result["usage"].get("total_tokens", 0),
            }

        if "model" in result:
            response_model = result["model"]

        return {
            "content": content,
            "usage": usage,
            "model": response_model,
            "provider_type": config.provider_type,
        }

    def _call_zhipu(
        self,
        config: LLMProviderConfig,
        messages: List[Dict],
        model: str,
        temperature: float,
        max_tokens: int,
        stream: bool = False,
    ) -> Dict[str, Any]:
        """
        调用智谱 GLM API
        智谱 GLM 已兼容 OpenAI 格式，直接复用 OpenAI 兼容调用
        """
        return self._call_openai_compatible(
            config, messages, model, temperature, max_tokens, stream
        )

    def _call_baidu(
        self,
        config: LLMProviderConfig,
        messages: List[Dict],
        model: str,
        temperature: float,
        max_tokens: int,
        stream: bool = False,
    ) -> Dict[str, Any]:
        """
        调用百度文心 API
        百度文心 API 兼容 OpenAI 格式，使用 Bearer Token 认证

        POST {api_base}/chat/completions
        Headers: Authorization: Bearer {api_key}
        """
        url = "{}/chat/completions".format(config.api_base.rstrip("/"))

        headers = {
            "Content-Type": "application/json",
            "Authorization": "Bearer {}".format(config.api_key),
        }

        payload = {
            "model": model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
        }

        if stream:
            payload["stream"] = True

        response = requests.post(
            url,
            headers=headers,
            json=payload,
            timeout=self.REQUEST_TIMEOUT,
        )

        if response.status_code != 200:
            error_detail = ""
            try:
                error_data = response.json()
                error_detail = error_data.get("error_msg", "")
                if not error_detail:
                    error_detail = json.dumps(error_data, ensure_ascii=False)
            except Exception:
                error_detail = response.text[:500] if response.text else "未知错误"

            raise RuntimeError(
                "百度文心 API 请求失败: HTTP {}, {}".format(
                    response.status_code, error_detail
                )
            )

        result = response.json()

        # 解析百度文心响应（兼容 OpenAI 格式）
        content = ""
        usage = {}
        response_model = model

        if "result" in result:
            # 百度原生格式: {"result": "...", "usage": {...}}
            content = result["result"]
            if "usage" in result:
                usage = {
                    "prompt_tokens": result["usage"].get("prompt_tokens", 0),
                    "completion_tokens": result["usage"].get("completion_tokens", 0),
                    "total_tokens": result["usage"].get("total_tokens", 0),
                }
        elif "choices" in result and len(result["choices"]) > 0:
            # OpenAI 兼容格式
            choice = result["choices"][0]
            message = choice.get("message", {})
            content = message.get("content", "")
            if "usage" in result:
                usage = {
                    "prompt_tokens": result["usage"].get("prompt_tokens", 0),
                    "completion_tokens": result["usage"].get("completion_tokens", 0),
                    "total_tokens": result["usage"].get("total_tokens", 0),
                }

        return {
            "content": content,
            "usage": usage,
            "model": response_model,
            "provider_type": config.provider_type,
        }

    def _call_spark(
        self,
        config: LLMProviderConfig,
        messages: List[Dict],
        model: str,
        temperature: float,
        max_tokens: int,
        stream: bool = False,
    ) -> Dict[str, Any]:
        """
        调用讯飞星火 API
        讯飞星火已兼容 OpenAI 格式，使用 Bearer Token 认证

        POST {api_base}/chat/completions
        Headers: Authorization: Bearer {api_key}
        """
        url = "{}/chat/completions".format(config.api_base.rstrip("/"))

        headers = {
            "Content-Type": "application/json",
            "Authorization": "Bearer {}".format(config.api_key),
        }

        payload = {
            "model": model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
        }

        if stream:
            payload["stream"] = True

        response = requests.post(
            url,
            headers=headers,
            json=payload,
            timeout=self.REQUEST_TIMEOUT,
        )

        if response.status_code != 200:
            error_detail = ""
            try:
                error_data = response.json()
                error_detail = error_data.get("error", {}).get("message", "")
                if not error_detail:
                    error_detail = json.dumps(error_data, ensure_ascii=False)
            except Exception:
                error_detail = response.text[:500] if response.text else "未知错误"

            raise RuntimeError(
                "讯飞星火 API 请求失败: HTTP {}, {}".format(
                    response.status_code, error_detail
                )
            )

        result = response.json()

        # 解析讯飞星火响应（兼容 OpenAI 格式）
        content = ""
        usage = {}
        response_model = model

        if "choices" in result and len(result["choices"]) > 0:
            choice = result["choices"][0]
            message = choice.get("message", {})
            content = message.get("content", "")

        if "usage" in result:
            usage = {
                "prompt_tokens": result["usage"].get("prompt_tokens", 0),
                "completion_tokens": result["usage"].get("completion_tokens", 0),
                "total_tokens": result["usage"].get("total_tokens", 0),
            }

        if "model" in result:
            response_model = result["model"]

        return {
            "content": content,
            "usage": usage,
            "model": response_model,
            "provider_type": config.provider_type,
        }


# ============================================================
# 全局实例
# ============================================================

llm_provider = LLMProvider()
