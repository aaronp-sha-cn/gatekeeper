"""
GateKeeper - 零信任架构 (ZTA) 策略引擎
实现基于多因素评估的零信任访问控制
"""

import os
import json
import threading
import ipaddress
from datetime import datetime
from typing import Dict, List, Optional

from config.logging_config import get_logger

logger = get_logger("zero_trust")

CONFIG_PATH = "/etc/gatekeeper/rules/zero_trust.json"
LOG_PATH = "/opt/gatekeeper/logs/zero_trust_access.log"


class ZeroTrustEngine:
    """零信任架构策略引擎"""

    def __init__(self):
        self._config = {
            "enabled": False,
            "default_action": "deny",   # deny 或 verify
            "policies": [],
            "trust_levels": {
                "high": {"score": 80, "description": "完全信任"},
                "medium": {"score": 50, "description": "需要验证"},
                "low": {"score": 20, "description": "受限访问"},
                "none": {"score": 0, "description": "拒绝访问"},
            },
            "factors": {
                "identity": {"weight": 30},      # 用户身份验证
                "device": {"weight": 20},        # 设备合规性
                "location": {"weight": 15},      # 网络位置
                "time": {"weight": 10},          # 时间策略
                "behavior": {"weight": 15},      # 行为分析
                "risk": {"weight": 10},          # 风险评分
            },
        }
        self._policies: List[dict] = []
        self._access_logs: List[dict] = []
        self._stats = {
            "total_requests": 0,
            "allowed": 0,
            "denied": 0,
            "mfa_required": 0,
            "verify_required": 0,
        }
        self._lock = threading.RLock()
        self._next_policy_id = 1
        self._load_config()

    # ---- 配置管理 ----

    def _load_config(self):
        """从配置文件加载配置"""
        try:
            if os.path.exists(CONFIG_PATH):
                with open(CONFIG_PATH, "r") as f:
                    saved = json.load(f)
                if "trust_levels" in saved:
                    self._config["trust_levels"].update(saved["trust_levels"])
                if "factors" in saved:
                    self._config["factors"].update(saved["factors"])
                if "default_action" in saved:
                    self._config["default_action"] = saved["default_action"]
                if "enabled" in saved:
                    self._config["enabled"] = saved["enabled"]
                if "policies" in saved:
                    for p in saved["policies"]:
                        p["id"] = self._next_policy_id
                        self._next_policy_id += 1
                        self._policies.append(p)
                logger.info("零信任策略配置已加载 ({} 条策略)".format(len(self._policies)))
        except Exception as e:
            logger.warning("加载零信任策略配置失败: {}".format(e))

    def _save_config(self):
        """保存配置到文件"""
        try:
            os.makedirs(os.path.dirname(CONFIG_PATH), exist_ok=True)
            save_data = {
                "enabled": self._config["enabled"],
                "default_action": self._config["default_action"],
                "trust_levels": self._config["trust_levels"],
                "factors": self._config["factors"],
                "policies": self._policies,
            }
            with open(CONFIG_PATH, "w") as f:
                json.dump(save_data, f, indent=2, ensure_ascii=False)
        except Exception as e:
            logger.error("保存零信任策略配置失败: {}".format(e))

    def configure(self, config: dict) -> dict:
        """更新配置"""
        try:
            with self._lock:
                for key in ["enabled", "default_action"]:
                    if key in config:
                        self._config[key] = config[key]
                if "trust_levels" in config:
                    self._config["trust_levels"].update(config["trust_levels"])
                if "factors" in config:
                    self._config["factors"].update(config["factors"])
                self._save_config()
                logger.info("零信任策略配置已更新")
                return {"status": "ok", "message": "配置已更新"}
        except Exception as e:
            logger.error("更新零信任策略配置失败: {}".format(e))
            return {"status": "error", "message": str(e)}

    def get_config(self) -> dict:
        """获取配置"""
        with self._lock:
            return {
                "enabled": self._config["enabled"],
                "default_action": self._config["default_action"],
                "trust_levels": self._config["trust_levels"],
                "factors": self._config["factors"],
            }

    # ---- 信任评估 ----

    def evaluate(self, context: dict) -> dict:
        """
        评估访问请求的信任等级

        context 包含:
        - user_id, username, role
        - device_id, device_type, device_compliant
        - source_ip, source_port
        - destination_ip, destination_port, protocol
        - time, day_of_week
        - behavior_score (from AI engine)
        - risk_score (from threat intel)

        返回:
        - trust_level: high/medium/low/none
        - trust_score: 0-100
        - action: allow/deny/verify/mfa_required
        - reasons: list of evaluation factors
        """
        factors = self._config["factors"]
        reasons = []
        factor_scores = {}

        # 1. 身份因素 (0-100)
        identity_score = 0
        username = context.get("username", "")
        role = context.get("role", "")
        if username:
            identity_score += 50
            if role in ("ADMIN", "SUPER_ADMIN"):
                identity_score += 30
            elif role == "OPERATOR":
                identity_score += 20
            else:
                identity_score += 10
        else:
            reasons.append("未提供用户身份")
        factor_scores["identity"] = identity_score

        # 2. 设备因素 (0-100)
        device_score = 0
        device_compliant = context.get("device_compliant", False)
        device_type = context.get("device_type", "")
        if device_compliant:
            device_score += 70
        if device_type in ("desktop", "laptop"):
            device_score += 20
        elif device_type in ("mobile", "tablet"):
            device_score += 10
        if device_type:
            device_score += 10  # 已知设备类型
        else:
            reasons.append("未知设备类型")
        factor_scores["device"] = device_score

        # 3. 位置因素 (0-100)
        location_score = 0
        source_ip = context.get("source_ip", "")
        try:
            if source_ip:
                ip = ipaddress.ip_address(source_ip)
                if ip.is_private:
                    location_score += 80
                elif ip.is_loopback:
                    location_score += 100
                else:
                    location_score += 30
                    reasons.append("来自公网IP: {}".format(source_ip))
            else:
                reasons.append("未知源IP地址")
        except ValueError:
            reasons.append("无效的IP地址: {}".format(source_ip))
        factor_scores["location"] = location_score

        # 4. 时间因素 (0-100)
        time_score = 100  # 默认工作时间满分
        access_time = context.get("time", "")
        day_of_week = context.get("day_of_week", "")
        if access_time:
            try:
                hour = int(str(access_time).split(":")[0])
                if 9 <= hour < 18:
                    time_score = 100
                elif 7 <= hour < 21:
                    time_score = 60
                else:
                    time_score = 20
                    reasons.append("非工作时间访问: {}".format(access_time))
            except (ValueError, IndexError):
                pass
        if day_of_week:
            if day_of_week.lower() in ("sat", "sunday", "周六", "周日"):
                time_score = max(time_score - 30, 0)
                reasons.append("周末访问")
        factor_scores["time"] = time_score

        # 5. 行为因素 (0-100)
        behavior_score = context.get("behavior_score", 50)
        if isinstance(behavior_score, (int, float)):
            factor_scores["behavior"] = min(max(int(behavior_score), 0), 100)
        else:
            factor_scores["behavior"] = 50
            reasons.append("无行为分析数据")

        # 6. 风险因素 (0-100, 100=无风险)
        risk_score = context.get("risk_score", 50)
        if isinstance(risk_score, (int, float)):
            factor_scores["risk"] = min(max(int(risk_score), 0), 100)
        else:
            factor_scores["risk"] = 50
            reasons.append("无威胁情报数据")

        # 计算加权总分
        total_score = 0
        total_weight = 0
        for factor_name, score in factor_scores.items():
            weight = factors.get(factor_name, {}).get("weight", 10)
            total_score += score * weight
            total_weight += weight

        if total_weight > 0:
            trust_score = int(total_score / total_weight)
        else:
            trust_score = 0

        trust_score = min(max(trust_score, 0), 100)

        # 确定信任等级
        trust_level = "none"
        trust_levels = self._config["trust_levels"]
        for level_name in ["high", "medium", "low", "none"]:
            threshold = trust_levels.get(level_name, {}).get("score", 0)
            if trust_score >= threshold:
                trust_level = level_name
                break

        # 确定动作
        if trust_level == "high":
            action = "allow"
        elif trust_level == "medium":
            action = "verify"
        elif trust_level == "low":
            action = "mfa_required"
        else:
            action = "deny"

        return {
            "trust_level": trust_level,
            "trust_score": trust_score,
            "action": action,
            "reasons": reasons,
            "factor_scores": factor_scores,
        }

    # ---- 策略管理 ----

    def add_policy(self, policy: dict) -> dict:
        """
        添加零信任策略

        策略格式:
        {
            "name": "管理员访问",
            "source": {"users": ["admin"], "roles": ["admin", "super_admin"], "ips": []},
            "destination": {"networks": ["10.0.0.0/8"], "ports": [443, 22], "apps": ["web_admin"]},
            "conditions": {"time": "09:00-18:00", "days": ["mon-fri"], "device_compliant": True, "mfa_required": True},
            "action": "allow",
            "enabled": True,
        }
        """
        try:
            with self._lock:
                if not policy.get("name"):
                    return {"status": "error", "message": "策略名称不能为空"}

                new_policy = {
                    "id": self._next_policy_id,
                    "name": policy.get("name", ""),
                    "source": policy.get("source", {}),
                    "destination": policy.get("destination", {}),
                    "conditions": policy.get("conditions", {}),
                    "action": policy.get("action", "deny"),
                    "enabled": policy.get("enabled", True),
                    "created_at": datetime.now().isoformat(),
                    "updated_at": datetime.now().isoformat(),
                }
                self._next_policy_id += 1
                self._policies.append(new_policy)
                self._save_config()

                logger.info("零信任策略已添加: {} (ID: {})".format(new_policy["name"], new_policy["id"]))
                return {
                    "status": "ok",
                    "message": "策略已添加",
                    "policy_id": new_policy["id"],
                }
        except Exception as e:
            logger.error("添加零信任策略失败: {}".format(e))
            return {"status": "error", "message": str(e)}

    def update_policy(self, policy_id: int, policy: dict) -> dict:
        """更新策略"""
        try:
            with self._lock:
                for p in self._policies:
                    if p["id"] == policy_id:
                        if "name" in policy:
                            p["name"] = policy["name"]
                        if "source" in policy:
                            p["source"] = policy["source"]
                        if "destination" in policy:
                            p["destination"] = policy["destination"]
                        if "conditions" in policy:
                            p["conditions"] = policy["conditions"]
                        if "action" in policy:
                            p["action"] = policy["action"]
                        if "enabled" in policy:
                            p["enabled"] = policy["enabled"]
                        p["updated_at"] = datetime.now().isoformat()
                        self._save_config()
                        logger.info("零信任策略已更新: ID={}".format(policy_id))
                        return {"status": "ok", "message": "策略已更新"}
                return {"status": "error", "message": "策略不存在 (ID: {})".format(policy_id)}
        except Exception as e:
            logger.error("更新零信任策略失败: {}".format(e))
            return {"status": "error", "message": str(e)}

    def delete_policy(self, policy_id: int) -> dict:
        """删除策略"""
        try:
            with self._lock:
                for i, p in enumerate(self._policies):
                    if p["id"] == policy_id:
                        name = p["name"]
                        self._policies.pop(i)
                        self._save_config()
                        logger.info("零信任策略已删除: {} (ID: {})".format(name, policy_id))
                        return {"status": "ok", "message": "策略已删除"}
                return {"status": "error", "message": "策略不存在 (ID: {})".format(policy_id)}
        except Exception as e:
            logger.error("删除零信任策略失败: {}".format(e))
            return {"status": "error", "message": str(e)}

    def get_policies(self) -> list:
        """获取所有策略"""
        with self._lock:
            return list(self._policies)

    # ---- 访问检查 ----

    def _match_policy(self, context: dict, policy: dict) -> bool:
        """检查 context 是否匹配策略"""
        if not policy.get("enabled", True):
            return False

        source = policy.get("source", {})
        destination = policy.get("destination", {})
        conditions = policy.get("conditions", {})

        # 匹配用户
        allowed_users = source.get("users", [])
        if allowed_users:
            username = context.get("username", "")
            if username not in allowed_users:
                return False

        # 匹配角色
        allowed_roles = source.get("roles", [])
        if allowed_roles:
            role = context.get("role", "")
            if role not in allowed_roles:
                return False

        # 匹配源 IP
        allowed_ips = source.get("ips", [])
        if allowed_ips:
            source_ip = context.get("source_ip", "")
            ip_matched = False
            for allowed in allowed_ips:
                try:
                    if "/" in allowed:
                        if ipaddress.ip_address(source_ip) in ipaddress.ip_network(allowed, strict=False):
                            ip_matched = True
                            break
                    elif source_ip == allowed:
                        ip_matched = True
                        break
                except (ValueError, TypeError):
                    continue
            if not ip_matched:
                return False

        # 匹配目标网络
        dest_networks = destination.get("networks", [])
        if dest_networks:
            dest_ip = context.get("destination_ip", "")
            net_matched = False
            for net in dest_networks:
                try:
                    if "/" in net:
                        if ipaddress.ip_address(dest_ip) in ipaddress.ip_network(net, strict=False):
                            net_matched = True
                            break
                    elif dest_ip == net:
                        net_matched = True
                        break
                except (ValueError, TypeError):
                    continue
            if not net_matched:
                return False

        # 匹配目标端口
        dest_ports = destination.get("ports", [])
        if dest_ports:
            dest_port = context.get("destination_port", 0)
            if int(dest_port) not in [int(p) for p in dest_ports]:
                return False

        # 匹配应用
        dest_apps = destination.get("apps", [])
        if dest_apps:
            app = context.get("app", "")
            if app not in dest_apps:
                return False

        # 匹配时间条件
        time_range = conditions.get("time", "")
        if time_range and "-" in time_range:
            try:
                access_time = context.get("time", "")
                if access_time:
                    hour = int(str(access_time).split(":")[0])
                    start_str, end_str = time_range.split("-")
                    start_hour = int(start_str.strip().split(":")[0])
                    end_hour = int(end_str.strip().split(":")[0])
                    if not (start_hour <= hour < end_hour):
                        return False
            except (ValueError, IndexError):
                pass

        # 匹配星期条件
        allowed_days = conditions.get("days", [])
        if allowed_days:
            day = context.get("day_of_week", "")
            day_matched = False
            for d in allowed_days:
                d_lower = d.lower()
                if d_lower == "mon-fri" and day.lower() not in ("sat", "sun", "周六", "周日"):
                    day_matched = True
                    break
                elif d_lower in day.lower():
                    day_matched = True
                    break
            if not day_matched:
                return False

        # 匹配设备合规性
        if conditions.get("device_compliant"):
            if not context.get("device_compliant", False):
                return False

        return True

    def check_access(self, context: dict) -> dict:
        """
        检查访问权限（综合策略匹配和信任评估）

        返回: {"allowed": bool, "action": str, "policy_matched": str, "trust_score": int}
        """
        try:
            with self._lock:
                self._stats["total_requests"] += 1

                if not self._config["enabled"]:
                    # 未启用时使用默认动作
                    default = self._config["default_action"]
                    result = {
                        "allowed": default != "deny",
                        "action": default,
                        "policy_matched": None,
                        "trust_score": 0,
                        "reason": "零信任引擎未启用",
                    }
                    self._log_access(context, result)
                    return result

                # 1. 尝试匹配策略
                matched_policy = None
                for policy in self._policies:
                    if self._match_policy(context, policy):
                        matched_policy = policy
                        break

                # 2. 评估信任等级
                evaluation = self.evaluate(context)
                trust_score = evaluation["trust_score"]
                trust_level = evaluation["trust_level"]

                # 3. 综合决策
                if matched_policy:
                    policy_action = matched_policy.get("action", "allow")
                    # 策略匹配但信任等级过低，需要额外验证
                    if trust_level == "none":
                        action = "deny"
                    elif trust_level == "low" and policy_action == "allow":
                        action = "mfa_required"
                    elif trust_level == "medium" and policy_action == "allow":
                        action = "verify"
                    else:
                        action = policy_action
                else:
                    # 无匹配策略，使用信任评估结果
                    action = evaluation["action"]

                allowed = action in ("allow",)
                result = {
                    "allowed": allowed,
                    "action": action,
                    "policy_matched": matched_policy.get("name") if matched_policy else None,
                    "policy_id": matched_policy.get("id") if matched_policy else None,
                    "trust_score": trust_score,
                    "trust_level": trust_level,
                    "reasons": evaluation.get("reasons", []),
                }

                # 更新统计
                if action == "allow":
                    self._stats["allowed"] += 1
                elif action == "deny":
                    self._stats["denied"] += 1
                elif action == "mfa_required":
                    self._stats["mfa_required"] += 1
                elif action == "verify":
                    self._stats["verify_required"] += 1

                self._log_access(context, result)
                return result

        except Exception as e:
            logger.error("零信任访问检查异常: {}".format(e))
            self._stats["denied"] += 1
            return {
                "allowed": False,
                "action": "deny",
                "policy_matched": None,
                "trust_score": 0,
                "reason": "检查异常: {}".format(str(e)),
            }

    def _log_access(self, context: dict, result: dict):
        """记录访问日志"""
        try:
            entry = {
                "timestamp": datetime.now().isoformat(),
                "username": context.get("username", ""),
                "source_ip": context.get("source_ip", ""),
                "destination_ip": context.get("destination_ip", ""),
                "destination_port": context.get("destination_port", ""),
                "protocol": context.get("protocol", ""),
                "action": result.get("action", ""),
                "allowed": result.get("allowed", False),
                "trust_score": result.get("trust_score", 0),
                "trust_level": result.get("trust_level", ""),
                "policy_matched": result.get("policy_matched", ""),
            }
            self._access_logs.append(entry)
            # 限制内存日志数量
            max_logs = 10000
            if len(self._access_logs) > max_logs:
                self._access_logs = self._access_logs[-max_logs:]
            # 写入文件
            try:
                log_dir = os.path.dirname(LOG_PATH)
                if log_dir:
                    os.makedirs(log_dir, exist_ok=True)
                with open(LOG_PATH, "a") as f:
                    f.write(json.dumps(entry, ensure_ascii=False) + "\n")
            except Exception:
                pass
        except Exception:
            pass

    def get_access_logs(self, limit=100) -> list:
        """获取访问日志"""
        with self._lock:
            logs = list(self._access_logs)
            logs.reverse()
            return logs[:limit]

    def get_stats(self) -> dict:
        """获取统计"""
        with self._lock:
            stats = dict(self._stats)
            stats["policy_count"] = len(self._policies)
            stats["enabled_policies"] = sum(
                1 for p in self._policies if p.get("enabled", True)
            )
            return stats


# 全局单例
_zero_trust_engine = None
_zero_trust_engine_lock = threading.Lock()


def get_zero_trust_engine() -> ZeroTrustEngine:
    """获取零信任引擎单例"""
    global _zero_trust_engine
    if _zero_trust_engine is None:
        with _zero_trust_engine_lock:
            if _zero_trust_engine is None:
                _zero_trust_engine = ZeroTrustEngine()
    return _zero_trust_engine
