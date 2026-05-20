"""
GateKeeper - 规则更新路由
管理 IDS、CVE、WAF、DNS 四大安全模块的规则更新、查询与导入
"""

import os
import tempfile
import threading

from flask import Blueprint, jsonify, request, render_template

from config.logging_config import get_logger
from flask_login import login_required
from web.routes.auth import super_admin_required
from web.app import _safe_error_message

logger = get_logger("rule_update_route")

rule_update_bp = Blueprint('rule_update', __name__)


def _get_engine():
    """延迟加载规则更新引擎，避免循环导入"""
    from security.rule_updater import RuleUpdateEngine
    return RuleUpdateEngine()


# ============================================================
# 页面路由
# ============================================================

@rule_update_bp.route('/')
@login_required
def index():
    """规则更新中心页面"""
    return render_template('rule_update.html')


# ============================================================
# API: 状态查询
# ============================================================

@rule_update_bp.route('/api/status')
@login_required
def api_status():
    """获取所有模块的更新状态"""
    try:
        engine = _get_engine()
        status = engine.get_update_status()
        return jsonify({"status": "ok", "data": status})
    except Exception as e:
        logger.error("获取更新状态失败: {}".format(e))
        return jsonify({"status": "error", "message": "获取更新状态失败: ，请联系管理员"}), 500


# ============================================================
# API: 规则更新
# ============================================================

@rule_update_bp.route('/api/update-all', methods=['POST'])
@super_admin_required
def api_update_all():
    """触发全部模块更新（后台线程）"""
    try:
        engine = _get_engine()

        def _run():
            try:
                engine.update_all()
            except Exception as e:
                logger.error("全模块更新失败: {}".format(e))

        t = threading.Thread(target=_run, daemon=True)
        t.start()
        return jsonify({"status": "ok", "message": "全模块更新已启动"})
    except Exception as e:
        logger.error("触发全模块更新失败: {}".format(e))
        return jsonify({"status": "error", "message": "触发更新失败: ，请联系管理员"}), 500


@rule_update_bp.route('/api/update/<module>', methods=['POST'])
@super_admin_required
def api_update_module(module):
    """触发指定模块更新"""
    valid_modules = {
        'ids': 'update_ids_rules',
        'cve': 'update_cve_database',
        'waf': 'update_waf_rules',
        'dns': 'update_dns_blacklist',
    }
    if module not in valid_modules:
        return jsonify({"status": "error", "message": "无效模块: {}".format(module)}), 400

    try:
        engine = _get_engine()
        method_name = valid_modules[module]
        update_fn = getattr(engine, method_name)

        def _run():
            try:
                update_fn()
            except Exception as e:
                logger.error("模块 {} 更新失败: {}".format(module, e))

        t = threading.Thread(target=_run, daemon=True)
        t.start()
        return jsonify({"status": "ok", "message": "模块 {} 更新已启动".format(module)})
    except Exception as e:
        logger.error("触发模块更新失败: {}".format(e))
        return jsonify({"status": "error", "message": "触发更新失败: ，请联系管理员"}), 500


# ============================================================
# API: 规则查询
# ============================================================

@rule_update_bp.route('/api/rules/ids')
@login_required
def api_rules_ids():
    """获取当前 IDS 规则列表"""
    try:
        engine = _get_engine()
        rules = engine.get_ids_rules()
        return jsonify({"status": "ok", "data": rules})
    except Exception as e:
        logger.error("获取 IDS 规则失败: {}".format(e))
        return jsonify({"status": "error", "message": "获取 IDS 规则失败: ，请联系管理员"}), 500


@rule_update_bp.route('/api/rules/cve')
@login_required
def api_rules_cve():
    """获取 CVE 数据库"""
    try:
        days = request.args.get('days', 90, type=int)
        engine = _get_engine()
        rules = engine.get_cve_database(days=days)
        return jsonify({"status": "ok", "data": rules})
    except Exception as e:
        logger.error("获取 CVE 数据库失败: {}".format(e))
        return jsonify({"status": "error", "message": "获取 CVE 数据库失败: ，请联系管理员"}), 500


@rule_update_bp.route('/api/rules/waf')
@login_required
def api_rules_waf():
    """获取当前 WAF 规则列表"""
    try:
        engine = _get_engine()
        rules = engine.get_waf_rules()
        return jsonify({"status": "ok", "data": rules})
    except Exception as e:
        logger.error("获取 WAF 规则失败: {}".format(e))
        return jsonify({"status": "error", "message": "获取 WAF 规则失败: ，请联系管理员"}), 500


@rule_update_bp.route('/api/rules/dns')
@login_required
def api_rules_dns():
    """获取 DNS 黑名单列表"""
    try:
        engine = _get_engine()
        rules = engine.get_dns_blacklist()
        return jsonify({"status": "ok", "data": rules})
    except Exception as e:
        logger.error("获取 DNS 黑名单失败: {}".format(e))
        return jsonify({"status": "error", "message": "获取 DNS 黑名单失败: ，请联系管理员"}), 500


# ============================================================
# API: 规则导入
# ============================================================

@rule_update_bp.route('/api/import/ids', methods=['POST'])
@super_admin_required
def api_import_ids():
    """从上传文件导入 IDS 规则"""
    try:
        if 'file' not in request.files:
            return jsonify({"status": "error", "message": "未找到上传文件"}), 400
        f = request.files['file']
        if not f.filename:
            return jsonify({"status": "error", "message": "文件名为空"}), 400

        # 保存到临时文件后导入
        suffix = '.rules' if not f.filename.endswith('.json') else '.json'
        with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
            f.save(tmp.name)
            tmp_path = tmp.name

        try:
            engine = _get_engine()
            result = engine.import_ids_rules(tmp_path)
            return jsonify({"status": "ok", "data": result})
        finally:
            os.unlink(tmp_path)
    except Exception as e:
        logger.error("导入 IDS 规则失败: {}".format(e))
        return jsonify({"status": "error", "message": "导入失败: ，请联系管理员"}), 500


@rule_update_bp.route('/api/import/waf', methods=['POST'])
@super_admin_required
def api_import_waf():
    """从上传文件导入 WAF 规则"""
    try:
        if 'file' not in request.files:
            return jsonify({"status": "error", "message": "未找到上传文件"}), 400
        f = request.files['file']
        if not f.filename:
            return jsonify({"status": "error", "message": "文件名为空"}), 400

        with tempfile.NamedTemporaryFile(delete=False, suffix='.json') as tmp:
            f.save(tmp.name)
            tmp_path = tmp.name

        try:
            engine = _get_engine()
            result = engine.import_waf_rules(tmp_path)
            return jsonify({"status": "ok", "data": result})
        finally:
            os.unlink(tmp_path)
    except Exception as e:
        logger.error("导入 WAF 规则失败: {}".format(e))
        return jsonify({"status": "error", "message": "导入失败: ，请联系管理员"}), 500


@rule_update_bp.route('/api/import/dns', methods=['POST'])
@super_admin_required
def api_import_dns():
    """从上传文件导入 DNS 黑名单"""
    try:
        if 'file' not in request.files:
            return jsonify({"status": "error", "message": "未找到上传文件"}), 400
        f = request.files['file']
        if not f.filename:
            return jsonify({"status": "error", "message": "文件名为空"}), 400

        suffix = '.json' if f.filename.endswith('.json') else '.txt'
        with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
            f.save(tmp.name)
            tmp_path = tmp.name

        try:
            engine = _get_engine()
            result = engine.import_dns_blacklist(tmp_path)
            return jsonify({"status": "ok", "data": result})
        finally:
            os.unlink(tmp_path)
    except Exception as e:
        logger.error("导入 DNS 黑名单失败: {}".format(e))
        return jsonify({"status": "error", "message": "导入失败: ，请联系管理员"}), 500


# ============================================================
# API: MISP 威胁情报
# ============================================================

def _get_ti_manager():
    """延迟加载威胁情报管理器，避免循环导入"""
    from ai_engine.threat_intelligence import ThreatIntelligenceManager
    return ThreatIntelligenceManager()


@rule_update_bp.route('/api/misp/status')
@login_required
def api_misp_status():
    """获取 MISP 连接状态和同步统计"""
    try:
        manager = _get_ti_manager()
        status = manager.get_misp_status()
        return jsonify({"status": "ok", "data": status})
    except Exception as e:
        logger.error("获取 MISP 状态失败: {}".format(e))
        return jsonify({"status": "error", "message": "获取 MISP 状态失败: ，请联系管理员"}), 500


@rule_update_bp.route('/api/misp/configure', methods=['POST'])
@super_admin_required
def api_misp_configure():
    """配置 MISP 情报源连接"""
    try:
        data = request.get_json(silent=True)
        if not data:
            return jsonify({"status": "error", "message": "请求体为空"}), 400

        url = data.get("url", "").strip()
        api_key = data.get("api_key", "").strip()
        verify_ssl = data.get("verify_ssl", True)

        if not url or not api_key:
            return jsonify({"status": "error", "message": "URL 和 API Key 不能为空"}), 400

        manager = _get_ti_manager()
        result = manager.configure_misp(url, api_key, verify_ssl=verify_ssl)
        return jsonify({"status": "ok", "data": result})
    except Exception as e:
        logger.error("配置 MISP 失败: {}".format(e))
        return jsonify({"status": "error", "message": "配置 MISP 失败: ，请联系管理员"}), 500


@rule_update_bp.route('/api/misp/sync', methods=['POST'])
@super_admin_required
def api_misp_sync():
    """触发 MISP 威胁情报同步（后台线程）"""
    try:
        manager = _get_ti_manager()

        # 检查是否已配置
        misp_status = manager.get_misp_status()
        if not misp_status.get("configured"):
            return jsonify({"status": "error", "message": "MISP 未配置，请先配置 MISP 连接"}), 400

        def _run():
            try:
                manager.sync_misp_threats()
            except Exception as e:
                logger.error("MISP 同步失败: {}".format(e))

        t = threading.Thread(target=_run, daemon=True)
        t.start()
        return jsonify({"status": "ok", "message": "MISP 同步已启动"})
    except Exception as e:
        logger.error("触发 MISP 同步失败: {}".format(e))
        return jsonify({"status": "error", "message": "触发同步失败: ，请联系管理员"}), 500
