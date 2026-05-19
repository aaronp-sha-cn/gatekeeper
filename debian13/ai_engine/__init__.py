"""
GateKeeper - AI引擎模块
提供流量分析、异常检测、IDS优化、漏洞扫描、自适应防御和威胁情报等AI功能
"""

import warnings

# 受保护的子模块导入，避免因缺少第三方依赖而导致整个模块无法加载
try:
    from ai_engine.traffic_analyzer import TrafficAnalyzer
except ImportError:
    TrafficAnalyzer = None
    warnings.warn("ai_engine.traffic_analyzer 导入失败(可能缺少numpy/sklearn)")

try:
    from ai_engine.anomaly_detector import AnomalyDetector
except ImportError:
    AnomalyDetector = None
    warnings.warn("ai_engine.anomaly_detector 导入失败(可能缺少numpy/sklearn)")

try:
    from ai_engine.ids_optimizer import IDSOptimizer
except ImportError:
    IDSOptimizer = None
    warnings.warn("ai_engine.ids_optimizer 导入失败(可能缺少numpy)")

try:
    from ai_engine.vuln_scanner import VulnerabilityScanner
except ImportError:
    VulnerabilityScanner = None

try:
    from ai_engine.adaptive_defense import AdaptiveDefense
except ImportError:
    AdaptiveDefense = None

try:
    from ai_engine.model_manager import ModelManager
except ImportError:
    ModelManager = None
    warnings.warn("ai_engine.model_manager 导入失败(可能缺少numpy/sklearn)")

try:
    from ai_engine.threat_intelligence import ThreatIntelligenceManager
except ImportError:
    ThreatIntelligenceManager = None

try:
    from ai_engine.llm_provider import LLMProvider, LLMProviderConfig, llm_provider, PROVIDER_TEMPLATES
except ImportError:
    LLMProvider = None
    LLMProviderConfig = None
    llm_provider = None
    PROVIDER_TEMPLATES = {}
    warnings.warn("ai_engine.llm_provider 导入失败(可能缺少requests)")

try:
    from ai_engine.ai_config import (
        get_ai_config,
        save_ai_config,
        delete_ai_config,
        get_provider_config,
        get_provider_template,
        get_default_provider,
        set_default_ai_provider,
        chat,
        test_provider_connection,
        validate_provider_config,
        validate_api_key,
        import_provider_configs,
        export_provider_configs,
        reset_to_templates,
        get_config_status,
    )
except ImportError:
    get_ai_config = None
    save_ai_config = None
    delete_ai_config = None
    get_provider_config = None
    get_provider_template = None
    get_default_provider = None
    set_default_ai_provider = None
    chat = None
    test_provider_connection = None
    validate_provider_config = None
    validate_api_key = None
    import_provider_configs = None
    export_provider_configs = None
    reset_to_templates = None
    get_config_status = None
    warnings.warn("ai_engine.ai_config 导入失败(可能缺少requests)")

__all__ = [
    "TrafficAnalyzer",
    "AnomalyDetector",
    "IDSOptimizer",
    "VulnerabilityScanner",
    "AdaptiveDefense",
    "ModelManager",
    "ThreatIntelligenceManager",
    "LLMProvider",
    "LLMProviderConfig",
    "llm_provider",
    "PROVIDER_TEMPLATES",
    "get_ai_config",
    "save_ai_config",
    "delete_ai_config",
    "get_provider_config",
    "get_provider_template",
    "get_default_provider",
    "set_default_ai_provider",
    "chat",
    "test_provider_connection",
    "validate_provider_config",
    "validate_api_key",
    "import_provider_configs",
    "export_provider_configs",
    "reset_to_templates",
    "get_config_status",
]
