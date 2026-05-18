"""
GateKeeper - 安全模块
包含入侵检测、威胁防御、网络隔离、DNS过滤、双因素认证、SIEM、合规检查、资产发现、网络设备基线检查、沙箱分析等安全功能
"""

# 使用延迟导入避免单个模块失败导致整个包不可用
def __getattr__(name):
    """延迟导入安全子模块"""
    _module_map = {
        'IDSEngine': ('.ids_engine', 'IDSEngine'),
        'get_ids_engine': ('.ids_engine', 'get_ids_engine'),
        'AttackSignature': ('.ids_engine', 'AttackSignature'),
        'WAFEngine': ('.waf_engine', 'WAFEngine'),
        'get_waf_engine': ('.waf_engine', 'get_waf_engine'),
        'WAFRule': ('.waf_engine', 'WAFRule'),
        'ZeroTrustEngine': ('.zero_trust', 'ZeroTrustEngine'),
        'get_zero_trust_engine': ('.zero_trust', 'get_zero_trust_engine'),
        'NetworkIsolationManager': ('.network_isolation', 'NetworkIsolationManager'),
        'get_isolation_manager': ('.network_isolation', 'get_isolation_manager'),
        'IsolationZone': ('.network_isolation', 'IsolationZone'),
        'IsolationRule': ('.network_isolation', 'IsolationRule'),
        'DNSFilterEngine': ('.dns_filter', 'DNSFilterEngine'),
        'get_dns_filter': ('.dns_filter', 'get_dns_filter'),
        'DNSFilterRule': ('.dns_filter', 'DNSFilterRule'),
        'DNSQueryLog': ('.dns_filter', 'DNSQueryLog'),
        'TwoFactorAuth': ('.two_factor', 'TwoFactorAuth'),
        'get_two_factor_auth': ('.two_factor', 'get_two_factor_auth'),
        'TOTPConfig': ('.two_factor', 'TOTPConfig'),
        'SIEMEngine': ('.siem_engine', 'SIEMEngine'),
        'get_siem_engine': ('.siem_engine', 'get_siem_engine'),
        'SIEMEvent': ('.siem_engine', 'SIEMEvent'),
        'SIEMCorrelationRule': ('.siem_engine', 'SIEMCorrelationRule'),
        'ComplianceChecker': ('.compliance_checker', 'ComplianceChecker'),
        'get_compliance_checker': ('.compliance_checker', 'get_compliance_checker'),
        'ComplianceCheck': ('.compliance_checker', 'ComplianceCheck'),
        'ComplianceReport': ('.compliance_checker', 'ComplianceReport'),
        'AssetDiscoveryManager': ('.asset_discovery', 'AssetDiscoveryManager'),
        'get_asset_discovery': ('.asset_discovery', 'get_asset_discovery'),
        'NetworkAsset': ('.asset_discovery', 'NetworkAsset'),
        'AssetScanTask': ('.asset_discovery', 'AssetScanTask'),
        'NTConfigChecker': ('.ntconfig_checker', 'NTConfigChecker'),
        'get_ntconfig_checker': ('.ntconfig_checker', 'get_ntconfig_checker'),
        'BaselineRule': ('.ntconfig_checker', 'BaselineRule'),
        'DeviceConfig': ('.ntconfig_checker', 'DeviceConfig'),
        'CheckTask': ('.ntconfig_checker', 'CheckTask'),
        'CheckResult': ('.ntconfig_checker', 'CheckResult'),
        'SandboxAnalyzer': ('.sandbox_analyzer', 'SandboxAnalyzer'),
        'get_sandbox_analyzer': ('.sandbox_analyzer', 'get_sandbox_analyzer'),
        'SandboxTask': ('.sandbox_analyzer', 'SandboxTask'),
        'SandboxReport': ('.sandbox_analyzer', 'SandboxReport'),
        'TaskStatus': ('.sandbox_analyzer', 'TaskStatus'),
        'RiskLevel': ('.sandbox_analyzer', 'RiskLevel'),
    }
    if name in _module_map:
        module_path, attr_name = _module_map[name]
        try:
            from importlib import import_module
            mod = import_module(module_path, package='security')
            return getattr(mod, attr_name)
        except Exception:
            raise AttributeError("module 'security' has no attribute '{}'".format(name))
    raise AttributeError("module 'security' has no attribute '{}'".format(name))

__all__ = [
    'IDSEngine', 'get_ids_engine', 'AttackSignature',
    'WAFEngine', 'get_waf_engine', 'WAFRule',
    'ZeroTrustEngine', 'get_zero_trust_engine',
    'NetworkIsolationManager', 'get_isolation_manager', 'IsolationZone', 'IsolationRule',
    'DNSFilterEngine', 'get_dns_filter', 'DNSFilterRule', 'DNSQueryLog',
    'TwoFactorAuth', 'get_two_factor_auth', 'TOTPConfig',
    'SIEMEngine', 'get_siem_engine', 'SIEMEvent', 'SIEMCorrelationRule',
    'ComplianceChecker', 'get_compliance_checker', 'ComplianceCheck', 'ComplianceReport',
    'AssetDiscoveryManager', 'get_asset_discovery', 'NetworkAsset', 'AssetScanTask',
    'NTConfigChecker', 'get_ntconfig_checker', 'BaselineRule', 'DeviceConfig', 'CheckTask', 'CheckResult',
    'SandboxAnalyzer', 'get_sandbox_analyzer', 'SandboxTask', 'SandboxReport', 'TaskStatus', 'RiskLevel',
]
