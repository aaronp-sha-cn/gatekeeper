"""
GateKeeper - DNS过滤引擎
提供DNS查询过滤、域名黑/白名单、分类拦截等功能
"""

import json
import fnmatch
import threading
import time
import sqlalchemy
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any

from sqlalchemy import Column, Integer, String, Boolean, DateTime, Text, BigInteger, Index
from sqlalchemy.sql import func

from config.database import Base
from config.logging_config import get_logger
from core.database import db_manager

logger = get_logger("dns_filter")


# ============================================================
# ORM 模型
# ============================================================

class DNSFilterRuleModel(Base):
    """DNS过滤规则表"""
    __tablename__ = "dns_filter_rules"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(128), nullable=False)
    domain = Column(String(256), nullable=False, index=True)
    rule_type = Column(String(32), nullable=False, default="blacklist")  # whitelist / blacklist / category
    category = Column(String(64), nullable=True)  # adult/gambling/malware/phishing/ad/tracking/social_media/custom
    action = Column(String(32), nullable=False, default="block")  # block / redirect / sinkhole
    redirect_to = Column(String(45), nullable=True)  # 重定向IP
    enabled = Column(Boolean, default=True, nullable=False)
    hit_count = Column(BigInteger, default=0, nullable=False)
    description = Column(Text, nullable=True)
    created_at = Column(DateTime, server_default=func.now(), nullable=False)

    __table_args__ = (
        Index("idx_dns_rule_type_enabled", "rule_type", "enabled"),
        Index("idx_dns_category", "category"),
    )

    def __repr__(self):
        return "<DNSFilterRule(id={}, domain='{}', type='{}', action='{}')>".format(
            self.id, self.domain, self.rule_type, self.action
        )


class DNSQueryLogModel(Base):
    """DNS查询日志表"""
    __tablename__ = "dns_query_logs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, server_default=func.now(), nullable=False, index=True)
    client_ip = Column(String(45), nullable=False, index=True)
    domain = Column(String(256), nullable=False, index=True)
    query_type = Column(String(16), nullable=False, default="A")  # A/AAAA/CNAME/MX/TXT/NS
    action = Column(String(32), nullable=False, default="allowed")  # allowed/blocked/redirected
    matched_rule = Column(String(256), nullable=True)
    category = Column(String(64), nullable=True)

    __table_args__ = (
        Index("idx_dns_log_timestamp", "timestamp"),
        Index("idx_dns_log_domain", "domain"),
        Index("idx_dns_log_client", "client_ip"),
    )

    def __repr__(self):
        return "<DNSQueryLog(id={}, domain='{}', action='{}')>".format(
            self.id, self.domain, self.action
        )


# ============================================================
# 业务类
# ============================================================

class DNSFilterRule:
    """DNS过滤规则（业务对象）"""

    def __init__(self, name="", domain="", rule_type="blacklist",
                 category="custom", action="block", redirect_to="",
                 enabled=True, hit_count=0, description="", rule_id=None):
        self.id = rule_id
        self.name = name
        self.domain = domain
        self.rule_type = rule_type
        self.category = category
        self.action = action
        self.redirect_to = redirect_to
        self.enabled = enabled
        self.hit_count = hit_count
        self.description = description
        self.created_at = None

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "domain": self.domain,
            "rule_type": self.rule_type,
            "category": self.category,
            "action": self.action,
            "redirect_to": self.redirect_to,
            "enabled": self.enabled,
            "hit_count": self.hit_count,
            "description": self.description,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }

    @classmethod
    def from_model(cls, model: DNSFilterRuleModel) -> "DNSFilterRule":
        """从ORM模型创建业务对象"""
        rule = cls(
            rule_id=model.id,
            name=model.name,
            domain=model.domain,
            rule_type=model.rule_type,
            category=model.category,
            action=model.action,
            redirect_to=model.redirect_to,
            enabled=model.enabled,
            hit_count=model.hit_count,
            description=model.description,
        )
        rule.created_at = model.created_at
        return rule


class DNSQueryLog:
    """DNS查询日志（业务对象）"""

    def __init__(self, client_ip="", domain="", query_type="A",
                 action="allowed", matched_rule="", category="", log_id=None):
        self.id = log_id
        self.timestamp = None
        self.client_ip = client_ip
        self.domain = domain
        self.query_type = query_type
        self.action = action
        self.matched_rule = matched_rule
        self.category = category

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "client_ip": self.client_ip,
            "domain": self.domain,
            "query_type": self.query_type,
            "action": self.action,
            "matched_rule": self.matched_rule,
            "category": self.category,
        }


# ============================================================
# 内置分类规则库
# ============================================================

BUILTIN_MALWARE_DOMAINS = [
    "*.malware-site.org", "*.trojan-download.com", "*.ransomware-c2.net",
    "*.botnet-control.info", "*.exploit-kit.biz", "*.drive-by-download.net",
    "*.backdoor-server.com", "*.keylogger-capture.org", "*.rootkit-server.net",
    "*.worm-spreader.com", "*.spyware-collect.biz", "*.adware-inject.net",
    "malware-distribution.com", "phishing-campaign.org", "fake-antivirus.net",
    "*.cryptominer-pool.com", "*.rat-server.org", "*.ddos-botnet.net",
    "*.payload-delivery.com", "*.shellcode-exec.net", "*.zero-day-exploit.biz",
    "*.apt-attack-c2.com", "*.fileless-malware.org", "*.macro-virus.net",
    "*.trojan-dropper.com", "*.info-stealer.biz", "*.banking-trojan.net",
    "*.clipper-malware.org", "*.cryptojacker.com", "*.form-grabber.net",
    "*.dns-tunneling.biz", "*.reverse-shell.org", "*.webshell-server.com",
    "*.phishing-kit.net", "*.scareware-page.com", "*.tech-support-scam.org",
    "*.exploit-server.biz", "*.c2-beacon.net", "*.bot-master.com",
    "*.malicious-update.org", "*.typosquat-domain.net", "*.homoglyph-attack.com",
    "*.subdomain-takeover.biz", "*.dns-rebinding.net", "*.watering-hole.com",
    "*.supply-chain-attack.org", "*.spear-phish.net", "*.whale-phishing.com",
    "*.bypass-uac.biz", "*.privilege-escalation.net", "*.lateral-movement.org",
    # 扩充 - 已知恶意软件域名
    "*.emotet-c2.com", "*.trickbot-dropper.net", "*.qakbot-loader.org",
    "*.cobalt-strike-c2.biz", "*.ryuk-ransomware.net", "*.conti-c2.com",
    "*.lockbit-c2.org", "*.blackcat-ransomware.net", "*.revil-c2.biz",
    "*.maze-ransomware.com", "*.sodinokibi-c2.net", "*.dridex-loader.org",
    "*.zeus-botnet.cc", "*.pony-stealer.biz", "*.formbook-c2.net",
    "*.redline-stealer.com", "*.racoon-stealer.org", "*.vidar-stealer.net",
    "*.agent-tesla-c2.biz",
]

BUILTIN_PHISHING_DOMAINS = [
    "*.secure-account-verify.com", "*.login-secure-update.net",
    "*.banking-secure-login.org", "*.paypal-secure-confirm.com",
    "*.apple-id-verify.net", "*.microsoft-account-alert.org",
    "*.amazon-order-confirm.com", "*.google-security-check.net",
    "*.facebook-security-update.org", "*.email-account-verify.com",
    "*.tax-refund-claim.net", "*.government-portal-login.org",
    "*.crypto-wallet-verify.com", "*.exchange-login-secure.net",
    "*.shipping-notification-confirm.org", "*.password-reset-urgent.com",
    "*.account-suspended-alert.net", "*.verify-identity-now.org",
    "*.secure-payment-confirm.com", "*.billing-update-required.net",
    "*.social-security-verify.org", "*.insurance-claim-confirm.com",
    "*.lottery-winner-notify.net", "*.inheritance-claim-fund.org",
    # 扩充 - 已知钓鱼域名
    "*.secure-login-verify.net", "*.account-secure-update.com",
    "*.banking-alert-verify.org", "*.paypal-payment-confirm.net",
    "*.apple-security-check.com", "*.microsoft-verify-account.org",
    "*.google-account-security.net", "*.facebook-login-alert.com",
    "*.amazon-verify-order.org", "*.netflix-billing-update.com",
    "*.steam-community-confirm.net", "*.dropbox-shared-file.com",
    "*.linkedin-verify-account.org", "*.twitter-security-alert.net",
    "*.paypal-transaction-confirm.com", "*.chase-bank-alert.org",
    "*.wells-fargo-verify.net", "*.bank-of-america-login.com",
]

BUILTIN_AD_TRACKING_DOMAINS = [
    "*.doubleclick.net", "*.googlesyndication.com", "*.googleadservices.com",
    "*.google-analytics.com", "*.adnxs.com", "*.adsrvr.org",
    "*.amazon-adsystem.com", "*.facebook.com/tr", "*.moatads.com",
    "*.rubiconproject.com", "*.pubmatic.com", "*.openx.net",
    "*.casalemedia.com", "*.indexexchange.com", "*.taboola.com",
    "*.outbrain.com", "*.criteo.com", "*.adroll.com",
    "*.quantserve.com", "*.scorecardresearch.com", "*.hotjar.com",
    "*.mixpanel.com", "*.segment.io", "*.amplitude.com",
    "*.newrelic.com", "*.sentry.io", "*.fullstory.com",
    "*.mouseflow.com", "*.crazyegg.com", "*.optimizely.com",
    "*.pingdom.net", "*.chartbeat.com", "*.disqus.com",
    # 扩充 - 已知广告/追踪域名
    "*.googleads.g.doubleclick.net", "*.advertising.com",
    "*.adform.net", "*.agkn.com", "*.adsymptotic.com",
    "*.bidswitch.net", "*.casalemedia.com", "*.criteo.com",
    "*.demdex.net", "*.exelator.com", "*.eyeota.net",
    "*.lijit.com", "*.media.net", "*.mediavine.com",
]

BUILTIN_MINING_DOMAINS = [
    "*.pool.minexmr.com", "*.xmr.pool.minergate.com",
    "*.stratum+tcp.pool.coinhive.com", "*.coinhive.com",
    "*.coin-hive.com", "*.cryptoloot.pro", "*.crypto-loot.com",
    "*.webmine.cz", "*.webminepool.com", "*.jsecoin.com",
    "*.minero.cc", "*.hashfor.cash", "*.crypto-webminer.com",
    "*.monerominer.rocks", "*.coinhave.com", "*.ppoi.org",
    # 扩充 - 已知挖矿域名
    "*.coinhive.com", "*.minero.cc", "*.crypto-loot.com",
    "*.webminepool.com", "*.jsecoin.com", "*.hashfor.cash",
    "*.coin-hive.com", "*.cryptoloot.pro", "*.coinhave.com",
    "*.ppoi.org",
]

BUILTIN_C2_DOMAINS = [
    "*.c2-server.onion", "*.beacon-c2.net", "*.command-control.org",
    "*.apt-c2-infrastructure.com", "*.cobalt-strike-c2.net",
    "*.metasploit-handler.org", "*.empire-c2.biz", "*.pupy-c2.net",
    "*.havoc-c2.com", "*.sliver-c2.org", "*.brute-ratel-c2.net",
    "*.mythic-c2.com", "*.posey-c2.org", "*.deimos-c2.net",
    # 扩充 - 已知C2通信域名
    "*.darkcomet-c2.org", "*.gh0st-c2.net", "*.venom-rat-c2.com",
    "*.nanocore-c2.biz", "*.remcos-c2.net", "*.limerat-c2.org",
    "*.asyncrat-c2.com",
]


class DNSFilterEngine:
    """DNS过滤引擎"""

    def __init__(self):
        """初始化DNS过滤引擎，加载规则"""
        self._lock = threading.Lock()
        self._initialized = False
        # 规则缓存
        self._rules_cache = None
        self._rules_cache_time = 0
        self._rules_cache_ttl = 60  # 缓存有效期60秒
        self._load_builtin_rules()

    def _load_builtin_rules(self):
        """加载内置分类规则"""
        if self._initialized:
            return

        try:
            with db_manager.get_session() as session:
                existing = session.query(DNSFilterRuleModel).filter(
                    DNSFilterRuleModel.category.in_(["malware", "phishing", "ad", "mining", "c2"])
                ).count()
                if existing >= 100:
                    self._initialized = True
                    logger.info("DNS过滤规则已存在 ({}条)，跳过内置规则加载".format(existing))
                    return

                builtin_rules = []

                # 恶意软件域名
                for domain in BUILTIN_MALWARE_DOMAINS:
                    builtin_rules.append(DNSFilterRuleModel(
                        name="内置恶意软件域名 - {}".format(domain),
                        domain=domain,
                        rule_type="category",
                        category="malware",
                        action="block",
                        enabled=True,
                        description="内置恶意软件域名黑名单",
                    ))

                # 钓鱼域名
                for domain in BUILTIN_PHISHING_DOMAINS:
                    builtin_rules.append(DNSFilterRuleModel(
                        name="内置钓鱼域名 - {}".format(domain),
                        domain=domain,
                        rule_type="category",
                        category="phishing",
                        action="block",
                        enabled=True,
                        description="内置钓鱼域名黑名单",
                    ))

                # 广告/追踪域名
                for domain in BUILTIN_AD_TRACKING_DOMAINS:
                    builtin_rules.append(DNSFilterRuleModel(
                        name="内置广告追踪域名 - {}".format(domain),
                        domain=domain,
                        rule_type="category",
                        category="ad",
                        action="block",
                        enabled=False,
                        description="内置广告/追踪域名（默认禁用）",
                    ))

                # 挖矿域名
                for domain in BUILTIN_MINING_DOMAINS:
                    builtin_rules.append(DNSFilterRuleModel(
                        name="内置挖矿域名 - {}".format(domain),
                        domain=domain,
                        rule_type="category",
                        category="mining",
                        action="block",
                        enabled=True,
                        description="内置加密货币挖矿域名黑名单",
                    ))

                # C2通信域名
                for domain in BUILTIN_C2_DOMAINS:
                    builtin_rules.append(DNSFilterRuleModel(
                        name="内置C2通信域名 - {}".format(domain),
                        domain=domain,
                        rule_type="category",
                        category="c2",
                        action="block",
                        enabled=True,
                        description="内置C2命令控制通信域名黑名单",
                    ))

                session.add_all(builtin_rules)
                session.commit()

            self._initialized = True
            logger.info("已加载 {} 条内置DNS过滤规则".format(len(builtin_rules)))

        except Exception as e:
            self._initialized = True  # 避免重复尝试
            logger.error("加载内置DNS过滤规则失败: {}".format(e))

    def _load_rules_cache(self, session=None) -> tuple:
        """
        加载规则到内存缓存

        Args:
            session: 可选的数据库会话。如果提供，在当前会话中查询；
                     如果不提供，创建独立会话（用于缓存预热场景）。

        Returns:
            (whitelist_rules, filter_rules) 元组
        """
        now = time.time()
        if self._rules_cache is not None and (now - self._rules_cache_time) < self._rules_cache_ttl:
            return self._rules_cache

        if session is not None:
            # 使用传入的事务会话查询，确保缓存与事务一致
            whitelist_rules = session.query(DNSFilterRuleModel).filter(
                DNSFilterRuleModel.enabled == True,
                DNSFilterRuleModel.rule_type == "whitelist",
            ).all()

            filter_rules = session.query(DNSFilterRuleModel).filter(
                DNSFilterRuleModel.enabled == True,
                DNSFilterRuleModel.rule_type.in_(["blacklist", "category"]),
            ).all()
        else:
            # 独立会话查询（缓存预热场景）
            with db_manager.get_session() as sess:
                whitelist_rules = sess.query(DNSFilterRuleModel).filter(
                    DNSFilterRuleModel.enabled == True,
                    DNSFilterRuleModel.rule_type == "whitelist",
                ).all()

                filter_rules = sess.query(DNSFilterRuleModel).filter(
                    DNSFilterRuleModel.enabled == True,
                    DNSFilterRuleModel.rule_type.in_(["blacklist", "category"]),
                ).all()

        self._rules_cache = (whitelist_rules, filter_rules)
        self._rules_cache_time = now
        return self._rules_cache

    def reload_cache(self):
        """手动刷新规则缓存"""
        with self._lock:
            self._rules_cache = None
            self._rules_cache_time = 0
            logger.info("DNS过滤规则缓存已刷新")

    def inspect_query(self, domain: str, query_type: str = "A",
                      client_ip: str = "0.0.0.0") -> Dict[str, Any]:
        """
        检查DNS查询，返回决策结果

        Args:
            domain: 查询的域名
            query_type: 查询类型 (A/AAAA/CNAME/MX/TXT/NS)
            client_ip: 客户端IP

        Returns:
            {
                "action": "allowed" | "blocked" | "redirected",
                "matched_rule": str | None,
                "category": str | None,
                "redirect_to": str | None,
                "domain": str,
                "query_type": str,
                "client_ip": str,
            }
        """
        domain_lower = domain.lower().strip()
        if not domain_lower:
            return self._build_result("allowed", domain, query_type, client_ip)

        try:
            with db_manager.get_session() as session:
                # 在事务内加载规则缓存，确保数据一致性
                whitelist_rules, filter_rules = self._load_rules_cache(session)

                # 1. 先检查白名单（白名单优先）
                for rule in whitelist_rules:
                    if self._match_domain(domain_lower, rule.domain.lower()):
                        self._increment_hit_count(session, rule.id)
                        self._log_query(session, client_ip, domain, query_type,
                                        "allowed", rule.name, "whitelist")
                        return self._build_result("allowed", domain, query_type,
                                                  client_ip, rule.name, "whitelist")

                # 2. 检查黑名单和分类规则
                # 按优先级排序: category优先匹配（内置规则更精确）
                for rule in filter_rules:
                    if self._match_domain(domain_lower, rule.domain.lower()):
                        self._increment_hit_count(session, rule.id)
                        action = rule.action
                        matched_name = rule.name
                        category = rule.category or rule.rule_type

                        self._log_query(session, client_ip, domain, query_type,
                                        action, matched_name, category)

                        result = self._build_result(action, domain, query_type,
                                                     client_ip, matched_name, category)
                        if action == "redirect" and rule.redirect_to:
                            result["redirect_to"] = rule.redirect_to
                        return result

                # 3. 未匹配任何规则，放行
                self._log_query(session, client_ip, domain, query_type,
                                "allowed", None, None)
                return self._build_result("allowed", domain, query_type, client_ip)

        except Exception as e:
            logger.error("DNS查询检查失败: {}".format(e))
            return self._build_result("allowed", domain, query_type, client_ip)

    def _build_result(self, action: str, domain: str, query_type: str,
                      client_ip: str, matched_rule: str = None,
                      category: str = None) -> dict:
        """构建决策结果"""
        return {
            "action": action,
            "matched_rule": matched_rule,
            "category": category,
            "redirect_to": None,
            "domain": domain,
            "query_type": query_type,
            "client_ip": client_ip,
        }

    def _match_domain(self, domain: str, pattern: str) -> bool:
        """
        域名匹配，支持通配符

        Args:
            domain: 实际查询的域名，如 "www.example.com"
            pattern: 规则中的域名模式，如 "*.example.com" 或 "example.com"

        Returns:
            是否匹配
        """
        if not domain or not pattern:
            return False

        # 精确匹配
        if domain == pattern:
            return True

        # 通配符匹配
        if "*" in pattern:
            # 将通配符模式转换为fnmatch兼容格式
            # *.example.com 应匹配 www.example.com, sub.example.com 等
            return fnmatch.fnmatch(domain, pattern)

        # 后缀匹配: 如果pattern是 "example.com"，也匹配 "www.example.com"
        if domain.endswith("." + pattern):
            return True

        return False

    def _increment_hit_count(self, session, rule_id: int):
        """递增规则命中计数"""
        try:
            session.query(DNSFilterRuleModel).filter(
                DNSFilterRuleModel.id == rule_id
            ).update({"hit_count": DNSFilterRuleModel.hit_count + 1})
        except Exception as e:
            logger.debug("更新规则命中计数失败: {}".format(e))

    def _log_query(self, session, client_ip: str, domain: str,
                   query_type: str, action: str,
                   matched_rule: str = None, category: str = None):
        """记录DNS查询日志"""
        try:
            log_entry = DNSQueryLogModel(
                timestamp=datetime.now(),
                client_ip=client_ip,
                domain=domain,
                query_type=query_type,
                action=action,
                matched_rule=matched_rule,
                category=category,
            )
            session.add(log_entry)
        except Exception as e:
            logger.debug("记录DNS查询日志失败: {}".format(e))

    def add_rule(self, name: str, domain: str, rule_type: str = "blacklist",
                 category: str = "custom", action: str = "block",
                 redirect_to: str = "", enabled: bool = True,
                 description: str = "") -> DNSFilterRule:
        """
        添加DNS过滤规则

        Args:
            name: 规则名称
            domain: 域名或通配符
            rule_type: 规则类型 (whitelist/blacklist/category)
            category: 分类
            action: 动作 (block/redirect/sinkhole)
            redirect_to: 重定向IP
            enabled: 是否启用
            description: 描述

        Returns:
            DNSFilterRule 业务对象
        """
        with db_manager.get_session() as session:
            model = DNSFilterRuleModel(
                name=name,
                domain=domain,
                rule_type=rule_type,
                category=category,
                action=action,
                redirect_to=redirect_to if redirect_to else None,
                enabled=enabled,
                description=description,
            )
            session.add(model)
            session.flush()
            session.refresh(model)
            rule = DNSFilterRule.from_model(model)
            logger.info("添加DNS过滤规则: {} ({})".format(name, domain))
            # 新增规则后刷新缓存
            self.reload_cache()
            return rule

    def remove_rule(self, rule_id: int) -> bool:
        """
        删除DNS过滤规则

        Args:
            rule_id: 规则ID

        Returns:
            是否删除成功
        """
        with db_manager.get_session() as session:
            model = session.query(DNSFilterRuleModel).filter_by(id=rule_id).first()
            if model:
                session.delete(model)
                logger.info("删除DNS过滤规则: ID={}".format(rule_id))
                self.reload_cache()
                return True
            return False

    def toggle_rule(self, rule_id: int, enabled: bool) -> bool:
        """
        启用/禁用规则

        Args:
            rule_id: 规则ID
            enabled: 是否启用

        Returns:
            是否操作成功
        """
        with db_manager.get_session() as session:
            model = session.query(DNSFilterRuleModel).filter_by(id=rule_id).first()
            if model:
                model.enabled = enabled
                session.flush()
                logger.info("{}DNS过滤规则: ID={}".format(
                    "启用" if enabled else "禁用", rule_id))
                self.reload_cache()
                return True
            return False

    def get_rules(self, rule_type: str = None, category: str = None,
                  enabled_only: bool = False) -> List[Dict]:
        """
        获取规则列表

        Args:
            rule_type: 按规则类型过滤
            category: 按分类过滤
            enabled_only: 仅返回已启用规则

        Returns:
            规则字典列表
        """
        with db_manager.get_session() as session:
            query = session.query(DNSFilterRuleModel)

            if rule_type:
                query = query.filter(DNSFilterRuleModel.rule_type == rule_type)
            if category:
                query = query.filter(DNSFilterRuleModel.category == category)
            if enabled_only:
                query = query.filter(DNSFilterRuleModel.enabled == True)

            rules = query.order_by(DNSFilterRuleModel.id.desc()).all()
            return [DNSFilterRule.from_model(r).to_dict() for r in rules]

    def get_logs(self, limit: int = 100, offset: int = 0,
                 domain: str = None, action: str = None,
                 client_ip: str = None) -> Dict:
        """
        获取DNS查询日志

        Args:
            limit: 返回数量
            offset: 偏移量
            domain: 按域名过滤
            action: 按动作过滤
            client_ip: 按客户端IP过滤

        Returns:
            {"total": int, "logs": list, "limit": int, "offset": int}
        """
        try:
            with db_manager.get_session() as session:
                query = session.query(DNSQueryLogModel)

                if domain:
                    like = "%{}%".format(domain)
                    query = query.filter(DNSQueryLogModel.domain.ilike(like))
                if action:
                    query = query.filter(DNSQueryLogModel.action == action)
                if client_ip:
                    query = query.filter(DNSQueryLogModel.client_ip == client_ip)

                total = query.count()
                logs = query.order_by(DNSQueryLogModel.timestamp.desc()) \
                    .offset(offset).limit(limit).all()

                return {
                    "total": total,
                    "limit": limit,
                    "offset": offset,
                    "logs": [
                        {
                            "id": log.id,
                            "timestamp": log.timestamp.isoformat() if log.timestamp else None,
                            "client_ip": log.client_ip,
                            "domain": log.domain,
                            "query_type": log.query_type,
                            "action": log.action,
                            "matched_rule": log.matched_rule,
                            "category": log.category,
                        }
                        for log in logs
                    ]
                }
        except Exception as e:
            logger.error("获取DNS查询日志失败: {}".format(e))
            return {"total": 0, "limit": limit, "offset": offset, "logs": []}

    def get_stats(self) -> Dict:
        """
        获取统计信息

        Returns:
            统计数据字典
        """
        try:
            with db_manager.get_session() as session:
                # 总规则数
                total_rules = session.query(DNSFilterRuleModel).count()
                enabled_rules = session.query(DNSFilterRuleModel).filter(
                    DNSFilterRuleModel.enabled == True
                ).count()

                # 今日查询统计
                today_start = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)

                today_queries = session.query(DNSQueryLogModel).filter(
                    DNSQueryLogModel.timestamp >= today_start
                ).count()

                today_blocked = session.query(DNSQueryLogModel).filter(
                    DNSQueryLogModel.timestamp >= today_start,
                    DNSQueryLogModel.action.in_(["blocked", "redirected"])
                ).count()

                # 总查询和拦截
                total_queries = session.query(DNSQueryLogModel).count()
                total_blocked = session.query(DNSQueryLogModel).filter(
                    DNSQueryLogModel.action.in_(["blocked", "redirected"])
                ).count()

                # 按分类统计拦截数
                category_stats = {}
                for row in session.query(
                    DNSQueryLogModel.category,
                    sqlalchemy.func.count(DNSQueryLogModel.id)
                ).filter(
                    DNSQueryLogModel.timestamp >= today_start,
                    DNSQueryLogModel.action.in_(["blocked", "redirected"]),
                    DNSQueryLogModel.category.isnot(None)
                ).group_by(DNSQueryLogModel.category).all():
                    if row[0]:
                        category_stats[row[0]] = row[1]

                # 按动作统计
                action_stats = {}
                for row in session.query(
                    DNSQueryLogModel.action,
                    sqlalchemy.func.count(DNSQueryLogModel.id)
                ).filter(
                    DNSQueryLogModel.timestamp >= today_start
                ).group_by(DNSQueryLogModel.action).all():
                    action_stats[row[0]] = row[1]

                # 按分类统计规则数
                rule_category_stats = {}
                for row in session.query(
                    DNSFilterRuleModel.category,
                    sqlalchemy.func.count(DNSFilterRuleModel.id)
                ).group_by(DNSFilterRuleModel.category).all():
                    if row[0]:
                        rule_category_stats[row[0]] = row[1]

                # 最近24小时每小时查询趋势
                hourly_trend = []
                for hours_ago in range(23, -1, -1):
                    hour_start = datetime.now() - timedelta(hours=hours_ago)
                    hour_end = hour_start + timedelta(hours=1)
                    count = session.query(DNSQueryLogModel).filter(
                        DNSQueryLogModel.timestamp >= hour_start,
                        DNSQueryLogModel.timestamp < hour_end
                    ).count()
                    hourly_trend.append({
                        "hour": hour_start.strftime("%H:00"),
                        "queries": count,
                    })

                # Top 10 被拦截域名
                top_blocked = []
                for row in session.query(
                    DNSQueryLogModel.domain,
                    sqlalchemy.func.count(DNSQueryLogModel.id)
                ).filter(
                    DNSQueryLogModel.action.in_(["blocked", "redirected"])
                ).group_by(DNSQueryLogModel.domain).order_by(
                    sqlalchemy.func.count(DNSQueryLogModel.id).desc()
                ).limit(10).all():
                    top_blocked.append({"domain": row[0], "count": row[1]})

                # Top 10 查询客户端
                top_clients = []
                for row in session.query(
                    DNSQueryLogModel.client_ip,
                    sqlalchemy.func.count(DNSQueryLogModel.id)
                ).group_by(DNSQueryLogModel.client_ip).order_by(
                    sqlalchemy.func.count(DNSQueryLogModel.id).desc()
                ).limit(10).all():
                    top_clients.append({"client_ip": row[0], "count": row[1]})

                block_rate = 0.0
                if today_queries > 0:
                    block_rate = round(today_blocked / today_queries * 100, 2)

                return {
                    "total_rules": total_rules,
                    "enabled_rules": enabled_rules,
                    "today_queries": today_queries,
                    "today_blocked": today_blocked,
                    "total_queries": total_queries,
                    "total_blocked": total_blocked,
                    "block_rate": block_rate,
                    "category_stats": category_stats,
                    "action_stats": action_stats,
                    "rule_category_stats": rule_category_stats,
                    "hourly_trend": hourly_trend,
                    "top_blocked_domains": top_blocked,
                    "top_clients": top_clients,
                }

        except Exception as e:
            logger.error("获取DNS过滤统计失败: {}".format(e))
            return {
                "total_rules": 0, "enabled_rules": 0,
                "today_queries": 0, "today_blocked": 0,
                "total_queries": 0, "total_blocked": 0,
                "block_rate": 0.0,
            }

    def import_rules(self, rules_data: List[Dict]) -> Dict:
        """
        批量导入规则

        Args:
            rules_data: 规则数据列表，每项包含 name, domain, rule_type 等字段

        Returns:
            {"success": int, "failed": int, "errors": list}
        """
        success_count = 0
        failed_count = 0
        errors = []

        for i, rule_data in enumerate(rules_data):
            try:
                name = rule_data.get("name", "").strip()
                domain = rule_data.get("domain", "").strip()
                rule_type = rule_data.get("rule_type", "blacklist").strip()
                category = rule_data.get("category", "custom").strip()
                action = rule_data.get("action", "block").strip()
                redirect_to = rule_data.get("redirect_to", "").strip()
                enabled = rule_data.get("enabled", True)
                description = rule_data.get("description", "").strip()

                if not name or not domain:
                    errors.append("第{}条: 名称和域名不能为空".format(i + 1))
                    failed_count += 1
                    continue

                valid_types = ["whitelist", "blacklist", "category"]
                if rule_type not in valid_types:
                    errors.append("第{}条: 无效的规则类型 '{}'".format(i + 1, rule_type))
                    failed_count += 1
                    continue

                valid_actions = ["block", "redirect", "sinkhole"]
                if action not in valid_actions:
                    errors.append("第{}条: 无效的动作 '{}'".format(i + 1, action))
                    failed_count += 1
                    continue

                self.add_rule(
                    name=name, domain=domain, rule_type=rule_type,
                    category=category, action=action,
                    redirect_to=redirect_to, enabled=enabled,
                    description=description,
                )
                success_count += 1

            except Exception as e:
                errors.append("第{}条: {}".format(i + 1, str(e)))
                failed_count += 1

        logger.info("批量导入DNS规则完成: 成功={}, 失败={}".format(success_count, failed_count))
        return {"success": success_count, "failed": failed_count, "errors": errors}

    def export_rules(self, rule_type: str = None, category: str = None) -> List[Dict]:
        """
        导出规则

        Args:
            rule_type: 按规则类型过滤
            category: 按分类过滤

        Returns:
            规则数据列表
        """
        rules = self.get_rules(rule_type=rule_type, category=category)
        # 导出时去除 id, hit_count, created_at 等运行时字段
        export_data = []
        for rule in rules:
            export_data.append({
                "name": rule["name"],
                "domain": rule["domain"],
                "rule_type": rule["rule_type"],
                "category": rule["category"],
                "action": rule["action"],
                "redirect_to": rule["redirect_to"],
                "enabled": rule["enabled"],
                "description": rule["description"],
            })
        return export_data

    def clear_logs(self, days: int = 30) -> Dict:
        """
        清理过期DNS查询日志

        Args:
            days: 保留最近几天的日志

        Returns:
            {"success": bool, "message": str}
        """
        try:
            cutoff = datetime.now() - timedelta(days=days)
            with db_manager.get_session() as session:
                count = session.query(DNSQueryLogModel).filter(
                    DNSQueryLogModel.timestamp < cutoff
                ).count()

                if count > 0:
                    session.query(DNSQueryLogModel).filter(
                        DNSQueryLogModel.timestamp < cutoff
                    ).delete()
                    session.commit()

                logger.info("已清理 {} 天前的DNS查询日志，共 {} 条".format(days, count))
                return {"success": True, "message": "已清理 {} 条日志".format(count)}

        except Exception as e:
            logger.error("清理DNS查询日志失败: {}".format(e))
            return {"success": False, "message": str(e)}


# ============================================================
# 单例
# ============================================================

_dns_filter_engine: Optional[DNSFilterEngine] = None
_dns_filter_engine_lock = threading.Lock()


def get_dns_filter() -> DNSFilterEngine:
    """获取DNS过滤引擎单例"""
    global _dns_filter_engine
    if _dns_filter_engine is None:
        with _dns_filter_engine_lock:
            if _dns_filter_engine is None:
                _dns_filter_engine = DNSFilterEngine()
    return _dns_filter_engine
