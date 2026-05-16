"""
GateKeeper - IDS管理路由
提供入侵检测系统的API接口
"""

from flask import Blueprint, jsonify, request, render_template
from flask_login import login_required, current_user

from web.routes.auth import admin_required

from sqlalchemy import func, desc
from datetime import datetime, timedelta

from core.database import db_manager
from config.logging_config import get_logger
from core.models import AttackLog, AttackType, AttackSeverity
from security.ids_engine import get_ids_engine
from web.app import _safe_error_message

logger = get_logger("ids_routes")

ids_bp = Blueprint("ids", __name__)


@ids_bp.route("/")
@login_required
def index():
    """IDS管理页面"""
    return render_template("ids.html")


@ids_bp.route("/api/stats")
@login_required
def get_stats():
    """
    获取IDS统计信息
    ---
    tags: [入侵检测]
    security:
      - cookieAuth: []
    description: 获取IDS引擎的实时统计信息，包括今日/本周攻击数、攻击类型分布、Top攻击源等
    responses:
      200:
        description: IDS统计信息
        schema:
          type: object
          properties:
            status:
              type: string
              example: ok
            data:
              type: object
              properties:
                realtime:
                  type: object
                today_count:
                  type: integer
                week_count:
                  type: integer
                type_distribution:
                  type: object
                severity_distribution:
                  type: object
                top_attackers:
                  type: array
                  items:
                    type: object
                    properties:
                      ip:
                        type: string
                      count:
                        type: integer
      401:
        description: 未认证
      500:
        description: 服务器内部错误
    """
    try:
        engine = get_ids_engine()
        stats = engine.get_stats()
        
        # 从数据库获取更详细的统计
        with db_manager.get_session() as session:
            # 今日攻击数
            today = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
            today_count = session.query(func.count(AttackLog.id)).filter(
                AttackLog.timestamp >= today
            ).scalar() or 0
            
            # 本周攻击数
            week_ago = today - timedelta(days=7)
            week_count = session.query(func.count(AttackLog.id)).filter(
                AttackLog.timestamp >= week_ago
            ).scalar() or 0
            
            # 按攻击类型统计
            type_stats = session.query(
                AttackLog.attack_type,
                func.count(AttackLog.id).label('count')
            ).group_by(AttackLog.attack_type).all()
            
            # 按严重程度统计
            severity_stats = session.query(
                AttackLog.severity,
                func.count(AttackLog.id).label('count')
            ).group_by(AttackLog.severity).all()
            
            # Top 10 攻击源IP
            top_attackers = session.query(
                AttackLog.src_ip,
                func.count(AttackLog.id).label('count')
            ).group_by(AttackLog.src_ip).order_by(desc('count')).limit(10).all()
            
            return jsonify({
                'status': 'ok',
                'data': {
                    'realtime': stats,
                    'today_count': today_count,
                    'week_count': week_count,
                    'type_distribution': {t.value: c for t, c in type_stats},
                    'severity_distribution': {s.value: c for s, c in severity_stats},
                    'top_attackers': [{'ip': ip, 'count': c} for ip, c in top_attackers]
                }
            })
    except Exception as e:
        logger.error(f"获取IDS统计失败: {e}")
        return jsonify(_safe_error_message(e)), 500


@ids_bp.route("/api/attacks")
@login_required
def get_attacks():
    """获取攻击日志列表"""
    try:
        # 分页参数
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 50, type=int)
        
        # 过滤参数
        attack_type = request.args.get('type')
        severity = request.args.get('severity')
        src_ip = request.args.get('src_ip')
        is_blocked = request.args.get('is_blocked')
        hours = request.args.get('hours', 24, type=int)
        
        with db_manager.get_session() as session:
            query = session.query(AttackLog)
            
            # 时间过滤
            if hours > 0:
                cutoff = datetime.now() - timedelta(hours=hours)
                query = query.filter(AttackLog.timestamp >= cutoff)
            
            # 类型过滤
            if attack_type:
                query = query.filter(AttackLog.attack_type == AttackType(attack_type))
            
            # 严重程度过滤
            if severity:
                query = query.filter(AttackLog.severity == AttackSeverity(severity))
            
            # IP过滤
            if src_ip:
                query = query.filter(AttackLog.src_ip == src_ip)
            
            # 阻断状态过滤
            if is_blocked is not None:
                query = query.filter(AttackLog.is_blocked == (is_blocked.lower() == 'true'))
            
            # 排序和分页
            total = query.count()
            logs = query.order_by(desc(AttackLog.timestamp)).offset((page - 1) * per_page).limit(per_page).all()
            
            return jsonify({
                'status': 'ok',
                'data': {
                    'total': total,
                    'page': page,
                    'per_page': per_page,
                    'logs': [{
                        'id': log.id,
                        'timestamp': log.timestamp.isoformat() if log.timestamp else None,
                        'src_ip': log.src_ip,
                        'dst_ip': log.dst_ip,
                        'dst_port': log.dst_port,
                        'attack_type': log.attack_type.value,
                        'severity': log.severity.value,
                        'signature': log.signature,
                        'description': log.description,
                        'payload_preview': log.payload_preview,
                        'protocol': log.protocol,
                        'is_blocked': log.is_blocked
                    } for log in logs]
                }
            })
    except Exception as e:
        logger.error(f"获取攻击日志失败: {e}")
        return jsonify(_safe_error_message(e)), 500


@ids_bp.route("/api/block", methods=['POST'])
@admin_required
def block_ip():
    """
    手动阻断IP
    ---
    tags: [入侵检测]
    security:
      - cookieAuth: []
    parameters:
      - name: body
        in: body
        required: true
        schema:
          type: object
          required:
            - ip
          properties:
            ip:
              type: string
              example: "192.168.1.100"
            duration:
              type: integer
              description: 阻断时长（秒），默认3600秒
              default: 3600
            reason:
              type: string
              description: 阻断原因
              default: "手动阻断"
    responses:
      200:
        description: IP已阻断
      400:
        description: 参数错误
      401:
        description: 未认证
      403:
        description: 权限不足
    """
    try:
        data = request.get_json()
        if not data:
            return jsonify({"status": "error", "message": "请求体不能为空"}), 400
        ip = data.get('ip')
        duration = data.get('duration', 3600)  # 默认1小时
        reason = data.get('reason', '手动阻断')
        
        if not ip:
            return jsonify({'status': 'error', 'message': 'IP地址不能为空'}), 400
        
        engine = get_ids_engine()
        engine.block_ip_manual(ip, duration, reason)
        
        logger.info(f"用户 {current_user.username} 手动阻断IP {ip}")
        return jsonify({'status': 'ok', 'message': f'IP {ip} 已阻断'})
    except Exception as e:
        logger.error(f"阻断IP失败: {e}")
        return jsonify(_safe_error_message(e)), 500


@ids_bp.route("/api/unblock", methods=['POST'])
@admin_required
def unblock_ip():
    """解除IP阻断"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({"status": "error", "message": "请求体不能为空"}), 400
        ip = data.get('ip')

        if not ip:
            return jsonify({'status': 'error', 'message': 'IP地址不能为空'}), 400

        engine = get_ids_engine()
        success = engine.unblock_ip_manual(ip)
        
        if success:
            logger.info(f"用户 {current_user.username} 解除IP {ip} 阻断")
            return jsonify({'status': 'ok', 'message': f'IP {ip} 已解除阻断'})
        else:
            return jsonify({'status': 'error', 'message': f'IP {ip} 不在阻断列表中'}), 404
    except Exception as e:
        logger.error(f"解除阻断失败: {e}")
        return jsonify(_safe_error_message(e)), 500


@ids_bp.route("/api/blocked-ips")
@login_required
def get_blocked_ips():
    """获取当前被阻断的IP列表"""
    try:
        engine = get_ids_engine()
        blocked_ips = engine.blocked_ips
        
        return jsonify({
            'status': 'ok',
            'data': {
                'count': len(blocked_ips),
                'ips': [
                    {
                        'ip': ip,
                        'unblock_time': unblock_time.isoformat()
                    }
                    for ip, unblock_time in blocked_ips.items()
                ]
            }
        })
    except Exception as e:
        logger.error(f"获取阻断列表失败: {e}")
        return jsonify(_safe_error_message(e)), 500


@ids_bp.route("/api/config", methods=['GET', 'POST'])
@admin_required
def config():
    """获取/设置IDS配置"""
    engine = get_ids_engine()
    
    if request.method == 'GET':
        return jsonify({
            'status': 'ok',
            'data': {
                'auto_block': engine.auto_block,
                'block_threshold': engine.block_threshold,
                'block_duration': engine.block_duration
            }
        })
    
    # POST - 更新配置
    try:
        data = request.get_json()
        
        if 'auto_block' in data:
            engine.auto_block = bool(data['auto_block'])
        if 'block_threshold' in data:
            engine.block_threshold = int(data['block_threshold'])
        if 'block_duration' in data:
            engine.block_duration = int(data['block_duration'])
        
        logger.info(f"用户 {current_user.username} 更新IDS配置")
        return jsonify({'status': 'ok', 'message': '配置已更新'})
    except Exception as e:
        logger.error(f"更新IDS配置失败: {e}")
        return jsonify(_safe_error_message(e)), 500
