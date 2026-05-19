"""
GateKeeper - VPN服务管理
提供WireGuard/IPSec/OpenVPN VPN服务管理功能
"""

import json
import uuid
import shutil
import subprocess
import ipaddress
import os
import threading
from datetime import datetime
from typing import Optional, List, Dict, Any

from sqlalchemy import (
    Column, Integer, String, Boolean, DateTime, Text,
    ForeignKey, Index, JSON, BigInteger
)
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func

from config.database import Base
from config.logging_config import get_logger
from core.database import db_manager

logger = get_logger("vpn_service")


# ============================================================
# 数据模型
# ============================================================

class VPNConfig(Base):
    """VPN配置表"""
    __tablename__ = "vpn_configs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(128), nullable=False, unique=True)
    vpn_type = Column(String(32), nullable=False)  # wireguard / ipsec / openvpn
    server_ip = Column(String(45), nullable=False)
    server_port = Column(Integer, nullable=False)
    client_ip_range = Column(String(45), nullable=False)  # 如 10.10.0.0/24
    dns_servers = Column(Text, nullable=True)  # JSON数组
    allowed_users = Column(Text, nullable=True)  # JSON数组
    enabled = Column(Boolean, default=False, nullable=False)
    mtu = Column(Integer, default=1420, nullable=False)
    keepalive = Column(Integer, default=25, nullable=False)
    config_text = Column(Text, nullable=True)  # 完整配置文件内容
    created_at = Column(DateTime, server_default=func.now(), nullable=False)
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now(), nullable=False)

    # 关系
    clients = relationship("VPNClient", back_populates="config", cascade="all, delete-orphan")

    # 索引
    __table_args__ = (
        Index("idx_vpn_config_type", "vpn_type"),
        Index("idx_vpn_config_enabled", "enabled"),
    )

    def __repr__(self):
        return "<VPNConfig(id={}, name='{}', type='{}')>".format(
            self.id, self.name, self.vpn_type
        )


class VPNClient(Base):
    """VPN客户端表"""
    __tablename__ = "vpn_clients"

    id = Column(Integer, primary_key=True, autoincrement=True)
    config_id = Column(Integer, ForeignKey("vpn_configs.id"), nullable=False)
    username = Column(String(128), nullable=False)
    public_key = Column(Text, nullable=True)  # WireGuard公钥
    assigned_ip = Column(String(45), nullable=True)
    connected = Column(Boolean, default=False, nullable=False)
    last_connected = Column(DateTime, nullable=True)
    bytes_sent = Column(BigInteger, default=0, nullable=False)
    bytes_received = Column(BigInteger, default=0, nullable=False)
    created_at = Column(DateTime, server_default=func.now(), nullable=False)

    # 关系
    config = relationship("VPNConfig", back_populates="clients")

    # 索引
    __table_args__ = (
        Index("idx_vpn_client_config", "config_id"),
        Index("idx_vpn_client_username", "username"),
    )

    def __repr__(self):
        return "<VPNClient(id={}, username='{}', ip='{}')>".format(
            self.id, self.username, self.assigned_ip
        )


# ============================================================
# VPN服务管理器
# ============================================================

class VPNService:
    """VPN服务管理器"""

    def __init__(self):
        self._logger = get_logger("vpn_service")
        self._logger.info("VPN服务管理器初始化完成")

    # ----------------------------------------------------------
    # 配置管理
    # ----------------------------------------------------------

    def create_config(self, name: str, vpn_type: str, server_ip: str,
                      port: int, ip_range: str, dns: str = "",
                      mtu: int = 1420, keepalive: int = 25) -> Dict[str, Any]:
        """
        创建VPN配置

        Args:
            name: 配置名称
            vpn_type: VPN类型 (wireguard/ipsec/openvpn)
            server_ip: 服务器IP
            port: 服务器端口
            ip_range: 客户端IP范围 (CIDR)
            dns: DNS服务器 (逗号分隔)
            mtu: MTU值
            keepalive: Keepalive间隔(秒)

        Returns:
            操作结果字典
        """
        try:
            # 验证VPN类型
            if vpn_type not in ("wireguard", "ipsec", "openvpn"):
                return {"status": "error", "message": "不支持的VPN类型: {}".format(vpn_type)}

            # 验证IP范围格式
            try:
                network = ipaddress.ip_network(ip_range, strict=False)
            except ValueError:
                return {"status": "error", "message": "无效的IP范围格式: {}".format(ip_range)}

            # 验证端口范围
            if not (1 <= port <= 65535):
                return {"status": "error", "message": "端口范围必须在1-65535之间"}

            # 解析DNS列表
            dns_list = [s.strip() for s in dns.split(",") if s.strip()] if dns else []

            # 检查名称是否已存在
            with db_manager.get_session() as session:
                existing = session.query(VPNConfig).filter_by(name=name).first()
                if existing:
                    return {"status": "error", "message": "配置名称已存在: {}".format(name)}

            # 生成配置文件内容
            config = VPNConfig(
                name=name,
                vpn_type=vpn_type,
                server_ip=server_ip,
                server_port=port,
                client_ip_range=ip_range,
                dns_servers=json.dumps(dns_list, ensure_ascii=False),
                allowed_users=json.dumps([], ensure_ascii=False),
                enabled=False,
                mtu=mtu,
                keepalive=keepalive,
            )

            # 生成配置文本
            config.config_text = self._generate_config_text(config)
            db_manager.add(config)

            self._logger.info("创建VPN配置: {} (类型: {})".format(name, vpn_type))
            return {
                "status": "ok",
                "message": "VPN配置创建成功",
                "data": self._config_to_dict(config),
            }

        except Exception as e:
            self._logger.error("创建VPN配置失败: {}".format(e))
            return {"status": "error", "message": str(e)}

    def delete_config(self, config_id: int) -> Dict[str, Any]:
        """删除VPN配置"""
        try:
            with db_manager.get_session() as session:
                config = session.query(VPNConfig).filter_by(id=config_id).first()
                if not config:
                    return {"status": "error", "message": "配置不存在: ID={}".format(config_id)}

                name = config.name
                session.delete(config)

            self._logger.info("删除VPN配置: {} (ID={})".format(name, config_id))
            return {"status": "ok", "message": "VPN配置已删除: {}".format(name)}

        except Exception as e:
            self._logger.error("删除VPN配置失败: {}".format(e))
            return {"status": "error", "message": str(e)}

    def toggle_config(self, config_id: int, enabled: bool) -> Dict[str, Any]:
        """启用/禁用VPN配置"""
        try:
            with db_manager.get_session() as session:
                config = session.query(VPNConfig).filter_by(id=config_id).first()
                if not config:
                    return {"status": "error", "message": "配置不存在: ID={}".format(config_id)}

                config.enabled = enabled
                session.flush()
                result = self._config_to_dict(config)

            action = "启用" if enabled else "禁用"
            self._logger.info("{}VPN配置: {} (ID={})".format(action, config.name, config_id))
            return {
                "status": "ok",
                "message": "VPN配置已{}".format(action),
                "data": result,
            }

        except Exception as e:
            self._logger.error("切换VPN配置状态失败: {}".format(e))
            return {"status": "error", "message": str(e)}

    def get_configs(self) -> List[Dict[str, Any]]:
        """获取所有VPN配置"""
        try:
            with db_manager.get_session() as session:
                configs = session.query(VPNConfig).order_by(VPNConfig.created_at.desc()).all()
                return [self._config_to_dict(c) for c in configs]
        except Exception as e:
            self._logger.error("获取VPN配置列表失败: {}".format(e))
            return []

    def get_config(self, config_id: int) -> Optional[Dict[str, Any]]:
        """获取单个VPN配置"""
        try:
            with db_manager.get_session() as session:
                config = session.query(VPNConfig).filter_by(id=config_id).first()
                if config:
                    return self._config_to_dict(config)
            return None
        except Exception as e:
            self._logger.error("获取VPN配置失败: {}".format(e))
            return None

    # ----------------------------------------------------------
    # 客户端管理
    # ----------------------------------------------------------

    def add_client(self, config_id: int, username: str,
                   public_key: str = "") -> Dict[str, Any]:
        """添加VPN客户端"""
        try:
            with db_manager.get_session() as session:
                config = session.query(VPNConfig).filter_by(id=config_id).first()
                if not config:
                    return {"status": "error", "message": "配置不存在: ID={}".format(config_id)}

                # 检查用户名是否已存在
                existing = session.query(VPNClient).filter_by(
                    config_id=config_id, username=username
                ).first()
                if existing:
                    return {"status": "error", "message": "客户端已存在: {}".format(username)}

                # 分配IP地址
                assigned_ip = self._allocate_ip(config, session)

                client = VPNClient(
                    config_id=config_id,
                    username=username,
                    public_key=public_key if config.vpn_type == "wireguard" else None,
                    assigned_ip=assigned_ip,
                )
                session.add(client)
                session.flush()

            self._logger.info("添加VPN客户端: {} (配置ID={}, IP={})".format(
                username, config_id, assigned_ip))
            return {
                "status": "ok",
                "message": "客户端添加成功",
                "data": {
                    "id": client.id,
                    "username": client.username,
                    "assigned_ip": assigned_ip,
                },
            }

        except Exception as e:
            self._logger.error("添加VPN客户端失败: {}".format(e))
            return {"status": "error", "message": str(e)}

    def remove_client(self, client_id: int) -> Dict[str, Any]:
        """移除VPN客户端"""
        try:
            with db_manager.get_session() as session:
                client = session.query(VPNClient).filter_by(id=client_id).first()
                if not client:
                    return {"status": "error", "message": "客户端不存在: ID={}".format(client_id)}

                username = client.username
                session.delete(client)

            self._logger.info("移除VPN客户端: {} (ID={})".format(username, client_id))
            return {"status": "ok", "message": "客户端已移除: {}".format(username)}

        except Exception as e:
            self._logger.error("移除VPN客户端失败: {}".format(e))
            return {"status": "error", "message": str(e)}

    def get_clients(self, config_id: int) -> List[Dict[str, Any]]:
        """获取配置的客户端列表"""
        try:
            with db_manager.get_session() as session:
                clients = session.query(VPNClient).filter_by(
                    config_id=config_id
                ).order_by(VPNClient.created_at.desc()).all()
                return [self._client_to_dict(c) for c in clients]
        except Exception as e:
            self._logger.error("获取VPN客户端列表失败: {}".format(e))
            return []

    def generate_client_config(self, config_id: int, client_id: int) -> Dict[str, Any]:
        """
        生成客户端配置文件

        Args:
            config_id: VPN配置ID
            client_id: 客户端ID

        Returns:
            包含配置文件内容的字典
        """
        try:
            with db_manager.get_session() as session:
                config = session.query(VPNConfig).filter_by(id=config_id).first()
                if not config:
                    return {"status": "error", "message": "配置不存在"}

                client = session.query(VPNClient).filter_by(
                    id=client_id, config_id=config_id
                ).first()
                if not client:
                    return {"status": "error", "message": "客户端不存在"}

                # 根据VPN类型生成客户端配置
                if config.vpn_type == "wireguard":
                    config_text = self._gen_wg_client_config(config, client)
                elif config.vpn_type == "ipsec":
                    config_text = self._gen_ipsec_client_config(config, client)
                elif config.vpn_type == "openvpn":
                    config_text = self._gen_openvpn_client_config(config, client)
                else:
                    return {"status": "error", "message": "不支持的VPN类型"}

                filename = "{}_{}".format(config.name, client.username)

            self._logger.info("生成客户端配置: {} (配置={}, 客户端={})".format(
                filename, config.name, client.username))
            return {
                "status": "ok",
                "data": {
                    "filename": filename,
                    "config_text": config_text,
                    "vpn_type": config.vpn_type,
                },
            }

        except Exception as e:
            self._logger.error("生成客户端配置失败: {}".format(e))
            return {"status": "error", "message": str(e)}

    # ----------------------------------------------------------
    # 服务控制
    # ----------------------------------------------------------

    def start_service(self, config_id: int) -> Dict[str, Any]:
        """启动VPN服务"""
        try:
            with db_manager.get_session() as session:
                config = session.query(VPNConfig).filter_by(id=config_id).first()
                if not config:
                    return {"status": "error", "message": "配置不存在: ID={}".format(config_id)}

                config.enabled = True
                config.config_text = self._generate_config_text(config)
                session.flush()

            self._logger.info("启动VPN服务: {} (ID={})".format(config.name, config_id))
            return {"status": "ok", "message": "VPN服务已启动: {}".format(config.name)}

        except Exception as e:
            self._logger.error("启动VPN服务失败: {}".format(e))
            return {"status": "error", "message": str(e)}

    def stop_service(self, config_id: int) -> Dict[str, Any]:
        """停止VPN服务"""
        try:
            with db_manager.get_session() as session:
                config = session.query(VPNConfig).filter_by(id=config_id).first()
                if not config:
                    return {"status": "error", "message": "配置不存在: ID={}".format(config_id)}

                config.enabled = False
                # 断开所有客户端
                session.query(VPNClient).filter_by(config_id=config_id).update(
                    {"connected": False}
                )
                session.flush()

            self._logger.info("停止VPN服务: {} (ID={})".format(config.name, config_id))
            return {"status": "ok", "message": "VPN服务已停止: {}".format(config.name)}

        except Exception as e:
            self._logger.error("停止VPN服务失败: {}".format(e))
            return {"status": "error", "message": str(e)}

    # ----------------------------------------------------------
    # 状态与统计
    # ----------------------------------------------------------

    def get_status(self) -> Dict[str, Any]:
        """获取VPN服务状态"""
        try:
            with db_manager.get_session() as session:
                configs = session.query(VPNConfig).all()
                clients = session.query(VPNClient).all()

                active_configs = [c for c in configs if c.enabled]
                connected_clients = [c for c in clients if c.connected]

                return {
                    "total_configs": len(configs),
                    "active_configs": len(active_configs),
                    "total_clients": len(clients),
                    "connected_clients": len(connected_clients),
                    "configs": [
                        {
                            "id": c.id,
                            "name": c.name,
                            "type": c.vpn_type,
                            "enabled": c.enabled,
                            "server": "{}:{}".format(c.server_ip, c.server_port),
                            "client_count": len(c.clients),
                            "connected_count": sum(1 for cl in c.clients if cl.connected),
                        }
                        for c in configs
                    ],
                }

        except Exception as e:
            self._logger.error("获取VPN状态失败: {}".format(e))
            return {
                "total_configs": 0, "active_configs": 0,
                "total_clients": 0, "connected_clients": 0, "configs": [],
            }

    def get_stats(self) -> Dict[str, Any]:
        """获取VPN统计信息"""
        try:
            with db_manager.get_session() as session:
                configs = session.query(VPNConfig).all()
                clients = session.query(VPNClient).all()

                total_bytes_sent = sum(c.bytes_sent for c in clients)
                total_bytes_received = sum(c.bytes_received for c in clients)

                # 按类型统计
                type_stats = {}
                for c in configs:
                    if c.vpn_type not in type_stats:
                        type_stats[c.vpn_type] = {"count": 0, "active": 0}
                    type_stats[c.vpn_type]["count"] += 1
                    if c.enabled:
                        type_stats[c.vpn_type]["active"] += 1

                return {
                    "total_configs": len(configs),
                    "active_configs": sum(1 for c in configs if c.enabled),
                    "total_clients": len(clients),
                    "connected_clients": sum(1 for c in clients if c.connected),
                    "total_bytes_sent": total_bytes_sent,
                    "total_bytes_received": total_bytes_received,
                    "total_traffic": total_bytes_sent + total_bytes_received,
                    "type_distribution": type_stats,
                }

        except Exception as e:
            self._logger.error("获取VPN统计失败: {}".format(e))
            return {
                "total_configs": 0, "active_configs": 0,
                "total_clients": 0, "connected_clients": 0,
                "total_bytes_sent": 0, "total_bytes_received": 0,
                "total_traffic": 0, "type_distribution": {},
            }

    # ----------------------------------------------------------
    # WireGuard配置生成
    # ----------------------------------------------------------

    def _gen_wg_server_config(self, config: VPNConfig) -> str:
        """生成WireGuard服务端配置"""
        dns_list = json.loads(config.dns_servers) if config.dns_servers else []
        dns_line = ", ".join(dns_list) if dns_list else "8.8.8.8, 8.8.4.4"

        lines = [
            "[Interface]",
            "PrivateKey = <SERVER_PRIVATE_KEY>",
            "Address = {}".format(config.server_ip),
            "ListenPort = {}".format(config.server_port),
            "MTU = {}".format(config.mtu),
            "",
            "# PostUp/PostDown规则 (NAT转发)",
            "PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -A FORWARD -o %i -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE",
            "PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -D FORWARD -o %i -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE",
            "",
            "# 客户端配置段",
        ]

        # 获取客户端列表
        try:
            with db_manager.get_session() as session:
                clients = session.query(VPNClient).filter_by(config_id=config.id).all()
                for client in clients:
                    lines.extend([
                        "",
                        "# Peer: {}".format(client.username),
                        "[Peer]",
                        "PublicKey = {}".format(client.public_key or "<CLIENT_PUBLIC_KEY>"),
                        "AllowedIPs = {}/32".format(client.assigned_ip),
                    ])
        except Exception:
            pass

        return "\n".join(lines)

    def _gen_wg_client_config(self, config: VPNConfig, client: VPNClient) -> str:
        """生成WireGuard客户端配置"""
        dns_list = json.loads(config.dns_servers) if config.dns_servers else []
        dns_line = ", ".join(dns_list) if dns_list else "8.8.8.8, 8.8.4.4"

        lines = [
            "[Interface]",
            "PrivateKey = <CLIENT_PRIVATE_KEY>",
            "Address = {}/32".format(client.assigned_ip),
            "DNS = {}".format(dns_line),
            "MTU = {}".format(config.mtu),
            "",
            "[Peer]",
            "PublicKey = <SERVER_PUBLIC_KEY>",
            "Endpoint = {}:{}".format(config.server_ip, config.server_port),
            "AllowedIPs = 0.0.0.0/0",
            "PersistentKeepalive = {}".format(config.keepalive),
        ]

        return "\n".join(lines)

    # ----------------------------------------------------------
    # IPSec配置生成
    # ----------------------------------------------------------

    def _gen_ipsec_config(self, config: VPNConfig) -> str:
        """生成IPSec服务端配置 (strongSwan格式)"""
        dns_list = json.loads(config.dns_servers) if config.dns_servers else []
        dns_line = ", ".join(dns_list) if dns_list else "8.8.8.8, 8.8.4.4"

        lines = [
            "# GateKeeper - IPSec VPN配置",
            "# 配置名称: {}".format(config.name),
            "# 生成时间: {}".format(datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
            "",
            "# ipsec.conf",
            "config setup",
            "    charondebug=\"ike 2, knl 2, cfg 2\"",
            "    uniqueids=no",
            "",
            "conn {}".format(config.name.replace(" ", "-").lower()),
            "    auto=add",
            "    keyexchange=ikev2",
            "    left={}".format(config.server_ip),
            "    leftsubnet=0.0.0.0/0",
            "    leftcert=server-cert.pem",
            "    leftsendcert=always",
            "    leftfirewall=yes",
            "    right=%any",
            "    rightauth=eap-mschapv2",
            "    rightsourceip={}".format(config.client_ip_range),
            "    rightdns={}".format(dns_line),
            "    ike=aes256gcm16-sha256-modp2048!",
            "    esp=aes256gcm16-sha256!",
            "",
            "# ipsec.secrets",
            ": RSA server-key.pem",
            "user1 : EAP \"password1\"",
        ]

        return "\n".join(lines)

    def _gen_ipsec_client_config(self, config: VPNConfig, client: VPNClient) -> str:
        """生成IPSec客户端配置"""
        lines = [
            "# GateKeeper - IPSec客户端配置",
            "# 配置名称: {}".format(config.name),
            "# 客户端: {}".format(client.username),
            "# 生成时间: {}".format(datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
            "",
            "conn {}".format(config.name.replace(" ", "-").lower()),
            "    auto=start",
            "    keyexchange=ikev2",
            "    left=%defaultroute",
            "    leftsourceip=%config",
            "    leftauth=eap-mschapv2",
            "    leftfirewall=yes",
            "    right={}".format(config.server_ip),
            "    rightauth=pubkey",
            "    rightsubnet=0.0.0.0/0",
            "    rightcert=server-cert.pem",
            "    rightid=@{}".format(config.server_ip),
            "    ike=aes256gcm16-sha256-modp2048!",
            "    esp=aes256gcm16-sha256!",
            "    eap_identity={}".format(client.username),
        ]

        return "\n".join(lines)

    # ----------------------------------------------------------
    # OpenVPN配置生成
    # ----------------------------------------------------------

    def _gen_openvpn_config(self, config: VPNConfig) -> str:
        """生成OpenVPN服务端配置"""
        dns_list = json.loads(config.dns_servers) if config.dns_servers else []

        lines = [
            "# GateKeeper - OpenVPN服务端配置",
            "# 配置名称: {}".format(config.name),
            "# 生成时间: {}".format(datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
            "",
            "# 基本配置",
            "port {}".format(config.server_port),
            "proto udp",
            "dev tun",
            "topology subnet",
            "",
            "# 证书和密钥",
            "ca ca.crt",
            "cert server.crt",
            "key server.key",
            "dh dh.pem",
            "tls-auth ta.key 0",
            "",
            "# 网络配置",
            "server {}".format(config.client_ip_range),
            "ifconfig-pool-persist ipp.txt",
            "",
            "# 保持连接",
            "keepalive {} {}".format(config.keepalive, config.keepalive * 4),
            "",
            "# 安全配置",
            "cipher AES-256-GCM",
            "auth SHA256",
            "",
            "# MTU",
            "tun-mtu {}".format(config.mtu),
            "fragment 1300",
            "mssfix 1250",
            "",
            "# 权限降级",
            "user nobody",
            "group nogroup",
            "persist-key",
            "persist-tun",
            "",
            "# 状态日志",
            "status openvpn-status.log",
            "log-append /var/log/openvpn.log",
            "verb 3",
            "",
            "# 客户端间通信",
            "client-to-client",
            "",
            "# NAT和路由",
            "push \"redirect-gateway def1 bypass-dhcp\"",
        ]

        for dns in dns_list:
            lines.append('push "dhcp-option DNS {}"'.format(dns))

        return "\n".join(lines)

    def _gen_openvpn_client_config(self, config: VPNConfig, client: VPNClient) -> str:
        """生成OpenVPN客户端配置"""
        lines = [
            "# GateKeeper - OpenVPN客户端配置",
            "# 配置名称: {}".format(config.name),
            "# 客户端: {}".format(client.username),
            "# 生成时间: {}".format(datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
            "",
            "client",
            "dev tun",
            "proto udp",
            "remote {} {}".format(config.server_ip, config.server_port),
            "resolv-retry infinite",
            "nobind",
            "",
            "# 用户认证",
            "auth-user-pass",
            "",
            "# 安全配置",
            "cipher AES-256-GCM",
            "auth SHA256",
            "",
            "# 证书",
            "remote-cert-tls server",
            "",
            "# MTU",
            "tun-mtu {}".format(config.mtu),
            "fragment 1300",
            "mssfix 1250",
            "",
            "# 保持连接",
            "keepalive {} {}".format(config.keepalive, config.keepalive * 4),
            "",
            "# 权限降级",
            "user nobody",
            "group nogroup",
            "persist-key",
            "persist-tun",
            "",
            "verb 3",
            "",
            "# 嵌入证书 (请替换为实际证书内容)",
            "<ca>",
            "-----BEGIN CERTIFICATE-----",
            "<CA证书内容>",
            "-----END CERTIFICATE-----",
            "</ca>",
            "",
            "<tls-auth>",
            "-----BEGIN OpenVPN Static key V1-----",
            "<TLS密钥内容>",
            "-----END OpenVPN Static key V1-----",
            "</tls-auth>",
            "key-direction 1",
        ]

        return "\n".join(lines)

    # ----------------------------------------------------------
    # 内部辅助方法
    # ----------------------------------------------------------

    def _generate_config_text(self, config: VPNConfig) -> str:
        """根据VPN类型生成服务端配置文本"""
        if config.vpn_type == "wireguard":
            return self._gen_wg_server_config(config)
        elif config.vpn_type == "ipsec":
            return self._gen_ipsec_config(config)
        elif config.vpn_type == "openvpn":
            return self._gen_openvpn_config(config)
        return ""

    def _allocate_ip(self, config: VPNConfig, session) -> str:
        """为客户端分配IP地址"""
        try:
            network = ipaddress.ip_network(config.client_ip_range, strict=False)
            # 获取已分配的IP
            existing_clients = session.query(VPNClient).filter_by(
                config_id=config.id
            ).all()
            used_ips = set()
            for c in existing_clients:
                if c.assigned_ip:
                    try:
                        used_ips.add(ipaddress.ip_address(c.assigned_ip))
                    except ValueError:
                        pass

            # 从网络中分配第一个可用IP（跳过网络地址和广播地址）
            for host in network.hosts():
                if host not in used_ips:
                    return str(host)

            return str(list(network.hosts())[0]) if list(network.hosts()) else ""

        except Exception as e:
            self._logger.error("分配IP地址失败: {}".format(e))
            return ""

    def _config_to_dict(self, config: VPNConfig) -> Dict[str, Any]:
        """将VPNConfig对象转为字典"""
        dns_list = []
        if config.dns_servers:
            try:
                dns_list = json.loads(config.dns_servers)
            except (json.JSONDecodeError, TypeError):
                pass

        allowed_users = []
        if config.allowed_users:
            try:
                allowed_users = json.loads(config.allowed_users)
            except (json.JSONDecodeError, TypeError):
                pass

        return {
            "id": config.id,
            "name": config.name,
            "vpn_type": config.vpn_type,
            "server_ip": config.server_ip,
            "server_port": config.server_port,
            "client_ip_range": config.client_ip_range,
            "dns_servers": dns_list,
            "allowed_users": allowed_users,
            "enabled": config.enabled,
            "mtu": config.mtu,
            "keepalive": config.keepalive,
            "config_text": config.config_text,
            "client_count": len(config.clients) if config.clients else 0,
            "connected_count": sum(1 for c in (config.clients or []) if c.connected),
            "created_at": config.created_at.isoformat() if config.created_at else None,
            "updated_at": config.updated_at.isoformat() if config.updated_at else None,
        }

    def _client_to_dict(self, client: VPNClient) -> Dict[str, Any]:
        """将VPNClient对象转为字典"""
        return {
            "id": client.id,
            "config_id": client.config_id,
            "username": client.username,
            "public_key": client.public_key,
            "assigned_ip": client.assigned_ip,
            "connected": client.connected,
            "last_connected": client.last_connected.isoformat() if client.last_connected else None,
            "bytes_sent": client.bytes_sent,
            "bytes_received": client.bytes_received,
            "created_at": client.created_at.isoformat() if client.created_at else None,
        }


# ============================================================
# 单例
# ============================================================

_vpn_service: Optional[VPNService] = None
_vpn_service_lock = threading.Lock()


def get_vpn_service() -> VPNService:
    """获取VPN服务管理器单例"""
    global _vpn_service
    if _vpn_service is None:
        with _vpn_service_lock:
            if _vpn_service is None:
                _vpn_service = VPNService()
    return _vpn_service


# ============================================================
# SSL VPN 服务
# ============================================================

class SSLVPNService:
    """
    SSL VPN服务管理器

    基于OpenVPN提供SSL VPN服务，支持客户端证书认证、
    双因素认证(2FA)、分流/全隧道模式等功能。
    配置文件存储于 /etc/gatekeeper/rules/ssl_vpn.json
    """

    CONFIG_PATH = "/etc/gatekeeper/rules/ssl_vpn.json"

    def __init__(self):
        """初始化SSL VPN服务"""
        self._logger = get_logger("vpn_service")
        self._server_ip = None
        self._port = 1194
        self._protocol = "udp"
        self._subnet = "10.8.0.0/24"
        self._dns_servers = None
        self._split_tunnel = True
        self._cipher = "AES-256-GCM"
        self._running = False
        self._clients = {}
        self._connections = []
        self._config = {}
        self._load_config()

    def _load_config(self):
        """
        从磁盘加载持久化配置

        Returns:
            None
        """
        try:
            if os.path.exists(self.CONFIG_PATH):
                with open(self.CONFIG_PATH, "r", encoding="utf-8") as f:
                    self._config = json.load(f)
                self._logger.info("SSL VPN配置已从磁盘加载")
            else:
                self._config = {}
        except Exception as e:
            self._logger.error("加载SSL VPN配置失败: {}".format(e))
            self._config = {}

    def _save_config(self):
        """
        将配置持久化到磁盘

        Returns:
            None
        """
        try:
            os.makedirs(os.path.dirname(self.CONFIG_PATH), exist_ok=True)
            with open(self.CONFIG_PATH, "w", encoding="utf-8") as f:
                json.dump(self._config, f, ensure_ascii=False, indent=2)
            self._logger.info("SSL VPN配置已保存到磁盘")
        except Exception as e:
            self._logger.error("保存SSL VPN配置失败: {}".format(e))

    def configure(self, server_ip, port=1194, protocol="udp", subnet="10.8.0.0/24",
                  dns_servers=None, split_tunnel=True, cipher="AES-256-GCM") -> dict:
        """
        配置SSL VPN服务参数

        Args:
            server_ip: 服务器IP地址
            port: 监听端口，默认1194
            protocol: 协议类型 (udp/tcp)，默认udp
            subnet: 客户端地址池，默认10.8.0.0/24
            dns_servers: DNS服务器列表，默认None
            split_tunnel: 是否启用分流模式，默认True
            cipher: 加密算法，默认AES-256-GCM

        Returns:
            包含操作结果的字典
        """
        try:
            # 验证子网格式
            try:
                ipaddress.ip_network(subnet, strict=False)
            except ValueError:
                return {"status": "error", "message": "无效的子网格式: {}".format(subnet)}

            # 验证协议类型
            if protocol not in ("udp", "tcp"):
                return {"status": "error", "message": "不支持的协议类型: {}，仅支持udp/tcp".format(protocol)}

            # 验证端口范围
            if not (1 <= port <= 65535):
                return {"status": "error", "message": "端口范围必须在1-65535之间"}

            self._server_ip = server_ip
            self._port = port
            self._protocol = protocol
            self._subnet = subnet
            self._dns_servers = dns_servers or ["8.8.8.8", "8.8.4.4"]
            self._split_tunnel = split_tunnel
            self._cipher = cipher

            self._config = {
                "server_ip": server_ip,
                "port": port,
                "protocol": protocol,
                "subnet": subnet,
                "dns_servers": self._dns_servers,
                "split_tunnel": split_tunnel,
                "cipher": cipher,
                "clients": self._config.get("clients", {}),
            }
            self._save_config()

            self._logger.info("SSL VPN配置完成: {}:{}".format(server_ip, port))
            return {
                "status": "ok",
                "message": "SSL VPN配置成功",
                "data": self._config,
            }

        except Exception as e:
            self._logger.error("SSL VPN配置失败: {}".format(e))
            return {"status": "error", "message": str(e)}

    def start(self) -> dict:
        """
        启动SSL VPN服务

        Returns:
            包含操作结果的字典
        """
        try:
            openvpn_bin = shutil.which("openvpn")
            if not openvpn_bin:
                return {
                    "status": "error",
                    "message": "未找到openvpn命令，请先安装OpenVPN",
                }

            if not self._server_ip:
                return {"status": "error", "message": "请先配置SSL VPN服务 (调用configure方法)"}

            # 生成服务端配置文件
            server_config = self._generate_server_config()
            config_file = "/etc/gatekeeper/rules/ssl_vpn_server.conf"
            os.makedirs(os.path.dirname(config_file), exist_ok=True)
            with open(config_file, "w", encoding="utf-8") as f:
                f.write(server_config)

            # 启动openvpn进程
            cmd = [openvpn_bin, "--config", config_file, "--daemon"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)

            if result.returncode != 0:
                self._logger.error("OpenVPN启动失败: {}".format(result.stderr))
                return {
                    "status": "error",
                    "message": "OpenVPN启动失败: {}".format(result.stderr.strip()),
                }

            self._running = True
            self._config["running"] = True
            self._save_config()

            self._logger.info("SSL VPN服务已启动")
            return {
                "status": "ok",
                "message": "SSL VPN服务已启动",
                "data": {"server_ip": self._server_ip, "port": self._port},
            }

        except subprocess.TimeoutExpired:
            return {"status": "error", "message": "OpenVPN启动超时"}
        except Exception as e:
            self._logger.error("SSL VPN启动失败: {}".format(e))
            return {"status": "error", "message": str(e)}

    def stop(self) -> dict:
        """
        停止SSL VPN服务

        Returns:
            包含操作结果的字典
        """
        try:
            killall_bin = shutil.which("killall")
            if killall_bin:
                subprocess.run([killall_bin, "openvpn"], capture_output=True, text=True, timeout=5)
            else:
                subprocess.run(["pkill", "-f", "openvpn"], capture_output=True, text=True, timeout=5)

            self._running = False
            self._connections = []
            self._config["running"] = False
            self._save_config()

            self._logger.info("SSL VPN服务已停止")
            return {"status": "ok", "message": "SSL VPN服务已停止"}

        except Exception as e:
            self._logger.error("SSL VPN停止失败: {}".format(e))
            return {"status": "error", "message": str(e)}

    def get_status(self) -> dict:
        """
        获取SSL VPN服务状态

        Returns:
            包含服务状态信息的字典
        """
        return {
            "status": "ok",
            "data": {
                "running": self._running,
                "server_ip": self._server_ip,
                "port": self._port,
                "protocol": self._protocol,
                "subnet": self._subnet,
                "cipher": self._cipher,
                "split_tunnel": self._split_tunnel,
                "client_count": len(self._clients),
                "active_connections": len(self._connections),
            },
        }

    def create_client(self, username, password=None, use_2fa=False) -> dict:
        """
        创建SSL VPN客户端并生成证书

        Args:
            username: 客户端用户名
            password: 客户端密码，可选
            use_2fa: 是否启用双因素认证，默认False

        Returns:
            包含操作结果的字典
        """
        try:
            if not self._server_ip:
                return {"status": "error", "message": "请先配置SSL VPN服务"}

            if username in self._clients:
                return {"status": "error", "message": "客户端已存在: {}".format(username)}

            # 分配IP地址
            network = ipaddress.ip_network(self._subnet, strict=False)
            used_ips = set()
            for client_info in self._clients.values():
                if client_info.get("assigned_ip"):
                    used_ips.add(ipaddress.ip_address(client_info["assigned_ip"]))
            assigned_ip = None
            for host in network.hosts():
                if host not in used_ips:
                    assigned_ip = str(host)
                    break
            if not assigned_ip:
                return {"status": "error", "message": "地址池已耗尽"}

            # 生成客户端证书信息（模拟）
            client_id = str(uuid.uuid4())[:8]
            cert_info = {
                "username": username,
                "assigned_ip": assigned_ip,
                "client_id": client_id,
                "use_2fa": use_2fa,
                "created_at": datetime.now().isoformat(),
                "revoked": False,
            }

            self._clients[username] = cert_info
            self._config["clients"] = self._clients
            self._save_config()

            self._logger.info("创建SSL VPN客户端: {} (IP={})".format(username, assigned_ip))
            return {
                "status": "ok",
                "message": "客户端创建成功",
                "data": cert_info,
            }

        except Exception as e:
            self._logger.error("创建SSL VPN客户端失败: {}".format(e))
            return {"status": "error", "message": str(e)}

    def revoke_client(self, username) -> dict:
        """
        吊销SSL VPN客户端证书

        Args:
            username: 要吊销的客户端用户名

        Returns:
            包含操作结果的字典
        """
        try:
            if username not in self._clients:
                return {"status": "error", "message": "客户端不存在: {}".format(username)}

            self._clients[username]["revoked"] = True
            self._config["clients"] = self._clients
            self._save_config()

            self._logger.info("吊销SSL VPN客户端: {}".format(username))
            return {"status": "ok", "message": "客户端证书已吊销: {}".format(username)}

        except Exception as e:
            self._logger.error("吊销SSL VPN客户端失败: {}".format(e))
            return {"status": "error", "message": str(e)}

    def get_client_config(self, username) -> dict:
        """
        获取客户端的.ovpn配置文件内容

        Args:
            username: 客户端用户名

        Returns:
            包含.ovpn配置内容的字典
        """
        try:
            if username not in self._clients:
                return {"status": "error", "message": "客户端不存在: {}".format(username)}

            client = self._clients[username]
            if client.get("revoked"):
                return {"status": "error", "message": "客户端证书已被吊销: {}".format(username)}

            ovpn_config = self._generate_ovpn_config(username, client)

            return {
                "status": "ok",
                "message": "客户端配置生成成功",
                "data": {
                    "username": username,
                    "filename": "{}.ovpn".format(username),
                    "config_content": ovpn_config,
                },
            }

        except Exception as e:
            self._logger.error("获取SSL VPN客户端配置失败: {}".format(e))
            return {"status": "error", "message": str(e)}

    def list_clients(self) -> list:
        """
        列出所有SSL VPN客户端

        Returns:
            客户端信息列表
        """
        return [
            {
                "username": info["username"],
                "assigned_ip": info.get("assigned_ip"),
                "use_2fa": info.get("use_2fa", False),
                "revoked": info.get("revoked", False),
                "created_at": info.get("created_at"),
            }
            for info in self._clients.values()
        ]

    def get_active_connections(self) -> list:
        """
        获取当前活跃的SSL VPN连接

        Returns:
            活跃连接列表
        """
        if not self._running:
            return []

        # 尝试通过openvpn管理接口获取连接信息
        try:
            result = subprocess.run(
                ["ps", "aux"], capture_output=True, text=True, timeout=5
            )
            connections = []
            for line in result.stdout.splitlines():
                if "openvpn" in line and "CLIENT_LIST" not in line:
                    connections.append({
                        "process": line.strip(),
                        "timestamp": datetime.now().isoformat(),
                    })
            return connections if connections else self._connections
        except Exception:
            return self._connections

    def get_stats(self) -> dict:
        """
        获取SSL VPN服务统计信息

        Returns:
            包含统计数据的字典
        """
        return {
            "status": "ok",
            "data": {
                "running": self._running,
                "total_clients": len(self._clients),
                "active_clients": len(self._connections),
                "revoked_clients": sum(1 for c in self._clients.values() if c.get("revoked")),
                "subnet": self._subnet,
                "used_ips": sum(1 for c in self._clients.values() if not c.get("revoked")),
            },
        }

    def _generate_server_config(self) -> str:
        """
        生成OpenVPN服务端配置文件内容

        Returns:
            服务端配置字符串
        """
        dns_push_lines = ""
        for dns in (self._dns_servers or ["8.8.8.8", "8.8.4.4"]):
            dns_push_lines += 'push "dhcp-option DNS {}"\n'.format(dns)

        redirect_line = ""
        if not self._split_tunnel:
            redirect_line = 'push "redirect-gateway def1 bypass-dhcp"\n'

        config = """# GateKeeper - SSL VPN服务端配置
# 生成时间: {timestamp}

# 基本配置
port {port}
proto {protocol}
dev tun0
topology subnet

# 证书和密钥
ca /etc/gatekeeper/rules/ssl_vpn/ca.crt
cert /etc/gatekeeper/rules/ssl_vpn/server.crt
key /etc/gatekeeper/rules/ssl_vpn/server.key
dh /etc/gatekeeper/rules/ssl_vpn/dh.pem
tls-auth /etc/gatekeeper/rules/ssl_vpn/ta.key 0

# 网络配置
server {subnet}
ifconfig-pool-persist /etc/gatekeeper/rules/ssl_vpn/ipp.txt

# 保持连接
keepalive 10 120

# 安全配置
cipher {cipher}
auth SHA256
remote-cert-tls client

# MTU
tun-mtu 1500
fragment 1300
mssfix 1250

# 权限降级
user nobody
group nogroup
persist-key
persist-tun

# 状态日志
status /var/log/gatekeeper/ssl_vpn-status.log
log-append /var/log/gatekeeper/ssl_vpn.log
verb 3

# 客户端间通信
client-to-client

# NAT和路由
{redirect}{dns}""".format(
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            port=self._port,
            protocol=self._protocol,
            subnet=self._subnet,
            cipher=self._cipher,
            redirect=redirect_line,
            dns=dns_push_lines,
        )
        return config

    def _generate_ovpn_config(self, username, client_info) -> str:
        """
        生成客户端.ovpn配置文件内容

        Args:
            username: 客户端用户名
            client_info: 客户端信息字典

        Returns:
            .ovpn配置文件内容字符串
        """
        remote_line = "remote {} {}".format(self._server_ip, self._port)
        proto_line = "proto {}".format(self._protocol)

        route_lines = ""
        if self._split_tunnel:
            route_lines = """
# 分流模式 - 仅路由VPN子网
route {subnet} net_gateway""".format(subnet=self._subnet)

        config = """# GateKeeper - SSL VPN客户端配置
# 客户端: {username}
# 生成时间: {timestamp}

client
dev tun
{proto}
{remote}
resolv-retry infinite
nobind

# 用户认证
auth-user-pass

# 安全配置
cipher {cipher}
auth SHA256
remote-cert-tls server

# MTU
tun-mtu 1500
fragment 1300
mssfix 1250

# 保持连接
keepalive 10 120

# 权限降级
user nobody
group nogroup
persist-key
persist-tun

verb 3
{route}

# 嵌入CA证书
<ca>
-----BEGIN CERTIFICATE-----
{ca_placeholder}
-----END CERTIFICATE-----
</ca>

# 嵌入客户端证书
<cert>
-----BEGIN CERTIFICATE-----
{cert_placeholder}
-----END CERTIFICATE-----
</cert>

# 嵌入客户端私钥
<key>
-----BEGIN PRIVATE KEY-----
{key_placeholder}
-----END PRIVATE KEY-----
</key>

# 嵌入TLS认证密钥
<tls-auth>
-----BEGIN OpenVPN Static key V1-----
{tls_placeholder}
-----END OpenVPN Static key V1-----
</tls-auth>
key-direction 1""".format(
            username=username,
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            proto=proto_line,
            remote=remote_line,
            cipher=self._cipher,
            route=route_lines,
            ca_placeholder="[请替换为CA证书内容]",
            cert_placeholder="[请替换为客户端证书内容]",
            key_placeholder="[请替换为客户端私钥内容]",
            tls_placeholder="[请替换为TLS认证密钥内容]",
        )
        return config


# ============================================================
# L2TP/IPSec VPN 服务
# ============================================================

class L2TPVPNService:
    """
    L2TP/IPSec VPN服务管理器

    基于xl2tpd和strongSwan提供L2TP/IPSec VPN服务，
    支持PSK预共享密钥和证书认证方式。
    配置文件存储于 /etc/gatekeeper/rules/l2tp_vpn.json
    """

    CONFIG_PATH = "/etc/gatekeeper/rules/l2tp_vpn.json"

    def __init__(self):
        """初始化L2TP/IPSec VPN服务"""
        self._logger = get_logger("vpn_service")
        self._server_ip = None
        self._psk = "shared_secret"
        self._subnet = "10.9.0.0/24"
        self._dns_servers = None
        self._mtu = 1400
        self._running = False
        self._users = {}
        self._connections = []
        self._config = {}
        self._load_config()

    def _load_config(self):
        """
        从磁盘加载持久化配置

        Returns:
            None
        """
        try:
            if os.path.exists(self.CONFIG_PATH):
                with open(self.CONFIG_PATH, "r", encoding="utf-8") as f:
                    self._config = json.load(f)
                self._logger.info("L2TP VPN配置已从磁盘加载")
            else:
                self._config = {}
        except Exception as e:
            self._logger.error("加载L2TP VPN配置失败: {}".format(e))
            self._config = {}

    def _save_config(self):
        """
        将配置持久化到磁盘

        Returns:
            None
        """
        try:
            os.makedirs(os.path.dirname(self.CONFIG_PATH), exist_ok=True)
            with open(self.CONFIG_PATH, "w", encoding="utf-8") as f:
                json.dump(self._config, f, ensure_ascii=False, indent=2)
            self._logger.info("L2TP VPN配置已保存到磁盘")
        except Exception as e:
            self._logger.error("保存L2TP VPN配置失败: {}".format(e))

    def configure(self, server_ip, psk="shared_secret", subnet="10.9.0.0/24",
                  dns_servers=None, mtu=1400) -> dict:
        """
        配置L2TP/IPSec VPN服务参数

        Args:
            server_ip: 服务器IP地址
            psk: IPSec预共享密钥，默认shared_secret
            subnet: 客户端地址池，默认10.9.0.0/24
            dns_servers: DNS服务器列表，默认None
            mtu: MTU值，默认1400

        Returns:
            包含操作结果的字典
        """
        try:
            # 验证子网格式
            try:
                ipaddress.ip_network(subnet, strict=False)
            except ValueError:
                return {"status": "error", "message": "无效的子网格式: {}".format(subnet)}

            # 检查必要工具
            xl2tpd_bin = shutil.which("xl2tpd")
            ipsec_bin = shutil.which("ipsec")
            if not xl2tpd_bin:
                return {
                    "status": "error",
                    "message": "未找到xl2tpd命令，请先安装xl2tpd",
                }
            if not ipsec_bin:
                return {
                    "status": "error",
                    "message": "未找到ipsec命令，请先安装strongSwan",
                }

            self._server_ip = server_ip
            self._psk = psk
            self._subnet = subnet
            self._dns_servers = dns_servers or ["8.8.8.8", "8.8.4.4"]
            self._mtu = mtu

            self._config = {
                "server_ip": server_ip,
                "psk": psk,
                "subnet": subnet,
                "dns_servers": self._dns_servers,
                "mtu": mtu,
                "users": self._config.get("users", {}),
            }
            self._save_config()

            self._logger.info("L2TP/IPSec VPN配置完成: {}".format(server_ip))
            return {
                "status": "ok",
                "message": "L2TP/IPSec VPN配置成功",
                "data": self._config,
            }

        except Exception as e:
            self._logger.error("L2TP/IPSec VPN配置失败: {}".format(e))
            return {"status": "error", "message": str(e)}

    def start(self) -> dict:
        """
        启动L2TP/IPSec VPN服务

        Returns:
            包含操作结果的字典
        """
        try:
            ipsec_bin = shutil.which("ipsec")
            xl2tpd_bin = shutil.which("xl2tpd")

            if not ipsec_bin:
                return {"status": "error", "message": "未找到ipsec命令，请先安装strongSwan"}
            if not xl2tpd_bin:
                return {"status": "error", "message": "未找到xl2tpd命令，请先安装xl2tpd"}

            if not self._server_ip:
                return {"status": "error", "message": "请先配置L2TP/IPSec VPN服务 (调用configure方法)"}

            # 启动IPSec
            ipsec_result = subprocess.run(
                [ipsec_bin, "start"], capture_output=True, text=True, timeout=10
            )
            if ipsec_result.returncode != 0:
                self._logger.warning("IPSec启动返回非零: {}".format(ipsec_result.stderr))

            # 启动xl2tpd
            xl2tpd_result = subprocess.run(
                [xl2tpd_bin], capture_output=True, text=True, timeout=10
            )
            if xl2tpd_result.returncode != 0:
                self._logger.warning("xl2tpd启动返回非零: {}".format(xl2tpd_result.stderr))

            self._running = True
            self._config["running"] = True
            self._save_config()

            self._logger.info("L2TP/IPSec VPN服务已启动")
            return {
                "status": "ok",
                "message": "L2TP/IPSec VPN服务已启动",
                "data": {"server_ip": self._server_ip, "subnet": self._subnet},
            }

        except subprocess.TimeoutExpired:
            return {"status": "error", "message": "L2TP/IPSec VPN启动超时"}
        except Exception as e:
            self._logger.error("L2TP/IPSec VPN启动失败: {}".format(e))
            return {"status": "error", "message": str(e)}

    def stop(self) -> dict:
        """
        停止L2TP/IPSec VPN服务

        Returns:
            包含操作结果的字典
        """
        try:
            ipsec_bin = shutil.which("ipsec")
            xl2tpd_bin = shutil.which("xl2tpd")

            if xl2tpd_bin:
                subprocess.run(
                    ["killall", "xl2tpd"], capture_output=True, text=True, timeout=5
                )

            if ipsec_bin:
                subprocess.run(
                    [ipsec_bin, "stop"], capture_output=True, text=True, timeout=10
                )

            self._running = False
            self._connections = []
            self._config["running"] = False
            self._save_config()

            self._logger.info("L2TP/IPSec VPN服务已停止")
            return {"status": "ok", "message": "L2TP/IPSec VPN服务已停止"}

        except Exception as e:
            self._logger.error("L2TP/IPSec VPN停止失败: {}".format(e))
            return {"status": "error", "message": str(e)}

    def get_status(self) -> dict:
        """
        获取L2TP/IPSec VPN服务状态

        Returns:
            包含服务状态信息的字典
        """
        return {
            "status": "ok",
            "data": {
                "running": self._running,
                "server_ip": self._server_ip,
                "subnet": self._subnet,
                "mtu": self._mtu,
                "user_count": len(self._users),
                "active_connections": len(self._connections),
            },
        }

    def create_user(self, username, password) -> dict:
        """
        创建L2TP VPN用户

        Args:
            username: 用户名
            password: 用户密码

        Returns:
            包含操作结果的字典
        """
        try:
            if not self._server_ip:
                return {"status": "error", "message": "请先配置L2TP/IPSec VPN服务"}

            if username in self._users:
                return {"status": "error", "message": "用户已存在: {}".format(username)}

            # 分配IP地址
            network = ipaddress.ip_network(self._subnet, strict=False)
            used_ips = set()
            for user_info in self._users.values():
                if user_info.get("assigned_ip"):
                    used_ips.add(ipaddress.ip_address(user_info["assigned_ip"]))
            assigned_ip = None
            for host in network.hosts():
                if host not in used_ips:
                    assigned_ip = str(host)
                    break
            if not assigned_ip:
                return {"status": "error", "message": "地址池已耗尽"}

            user_info = {
                "username": username,
                "assigned_ip": assigned_ip,
                "created_at": datetime.now().isoformat(),
            }

            self._users[username] = user_info
            self._config["users"] = self._users
            self._save_config()

            self._logger.info("创建L2TP VPN用户: {} (IP={})".format(username, assigned_ip))
            return {
                "status": "ok",
                "message": "用户创建成功",
                "data": user_info,
            }

        except Exception as e:
            self._logger.error("创建L2TP VPN用户失败: {}".format(e))
            return {"status": "error", "message": str(e)}

    def delete_user(self, username) -> dict:
        """
        删除L2TP VPN用户

        Args:
            username: 要删除的用户名

        Returns:
            包含操作结果的字典
        """
        try:
            if username not in self._users:
                return {"status": "error", "message": "用户不存在: {}".format(username)}

            del self._users[username]
            self._config["users"] = self._users
            self._save_config()

            self._logger.info("删除L2TP VPN用户: {}".format(username))
            return {"status": "ok", "message": "用户已删除: {}".format(username)}

        except Exception as e:
            self._logger.error("删除L2TP VPN用户失败: {}".format(e))
            return {"status": "error", "message": str(e)}

    def list_users(self) -> list:
        """
        列出所有L2TP VPN用户

        Returns:
            用户信息列表
        """
        return [
            {
                "username": info["username"],
                "assigned_ip": info.get("assigned_ip"),
                "created_at": info.get("created_at"),
            }
            for info in self._users.values()
        ]

    def get_active_connections(self) -> list:
        """
        获取当前活跃的L2TP/IPSec VPN连接

        Returns:
            活跃连接列表
        """
        if not self._running:
            return []

        try:
            ipsec_bin = shutil.which("ipsec")
            if ipsec_bin:
                result = subprocess.run(
                    [ipsec_bin, "statusall"],
                    capture_output=True, text=True, timeout=5
                )
                connections = []
                for line in result.stdout.splitlines():
                    if "ESTABLISHED" in line:
                        connections.append({
                            "info": line.strip(),
                            "timestamp": datetime.now().isoformat(),
                        })
                return connections if connections else self._connections
            return self._connections
        except Exception:
            return self._connections

    def get_stats(self) -> dict:
        """
        获取L2TP/IPSec VPN服务统计信息

        Returns:
            包含统计数据的字典
        """
        return {
            "status": "ok",
            "data": {
                "running": self._running,
                "total_users": len(self._users),
                "active_connections": len(self._connections),
                "subnet": self._subnet,
                "used_ips": len(self._users),
            },
        }


# ============================================================
# PPTP VPN 服务
# ============================================================

_PPTP_SECURITY_WARNING = (
    "[安全警告] PPTP协议已被证实存在严重安全漏洞，"
    "不支持现代加密标准，容易被窃听和攻击。"
    "强烈建议使用IPSec或SSL VPN替代PPTP。"
    "仅在兼容性需求下使用，并确保在受信任的网络环境中部署。"
)


class PPTPVPNService:
    """
    PPTP VPN服务管理器

    基于pptpd提供PPTP VPN服务，使用MS-CHAP v2认证。

    注意：PPTP协议已被证实存在严重安全漏洞，不支持现代加密标准。
    强烈建议使用IPSec或SSL VPN替代PPTP。
    仅在兼容性需求下使用，并确保在受信任的网络环境中部署。
    配置文件存储于 /etc/gatekeeper/rules/pptp_vpn.json
    """

    CONFIG_PATH = "/etc/gatekeeper/rules/pptp_vpn.json"

    def __init__(self):
        """初始化PPTP VPN服务"""
        self._logger = get_logger("vpn_service")
        self._logger.warning(_PPTP_SECURITY_WARNING)
        self._server_ip = None
        self._subnet = "10.10.0.0/24"
        self._dns_servers = None
        self._running = False
        self._users = {}
        self._connections = []
        self._config = {}
        self._load_config()

    def _load_config(self):
        """
        从磁盘加载持久化配置

        Returns:
            None
        """
        try:
            if os.path.exists(self.CONFIG_PATH):
                with open(self.CONFIG_PATH, "r", encoding="utf-8") as f:
                    self._config = json.load(f)
                self._logger.info("PPTP VPN配置已从磁盘加载")
            else:
                self._config = {}
        except Exception as e:
            self._logger.error("加载PPTP VPN配置失败: {}".format(e))
            self._config = {}

    def _save_config(self):
        """
        将配置持久化到磁盘

        Returns:
            None
        """
        try:
            os.makedirs(os.path.dirname(self.CONFIG_PATH), exist_ok=True)
            with open(self.CONFIG_PATH, "w", encoding="utf-8") as f:
                json.dump(self._config, f, ensure_ascii=False, indent=2)
            self._logger.info("PPTP VPN配置已保存到磁盘")
        except Exception as e:
            self._logger.error("保存PPTP VPN配置失败: {}".format(e))

    def configure(self, server_ip, subnet="10.10.0.0/24", dns_servers=None) -> dict:
        """
        配置PPTP VPN服务参数

        Args:
            server_ip: 服务器IP地址
            subnet: 客户端地址池，默认10.10.0.0/24
            dns_servers: DNS服务器列表，默认None

        Returns:
            包含操作结果的字典
        """
        try:
            self._logger.warning(_PPTP_SECURITY_WARNING)

            # 验证子网格式
            try:
                ipaddress.ip_network(subnet, strict=False)
            except ValueError:
                return {"status": "error", "message": "无效的子网格式: {}".format(subnet)}

            # 检查pptpd是否安装
            pptpd_bin = shutil.which("pptpd")
            if not pptpd_bin:
                return {
                    "status": "error",
                    "message": "未找到pptpd命令，请先安装pptpd",
                }

            self._server_ip = server_ip
            self._subnet = subnet
            self._dns_servers = dns_servers or ["8.8.8.8", "8.8.4.4"]

            self._config = {
                "server_ip": server_ip,
                "subnet": subnet,
                "dns_servers": self._dns_servers,
                "users": self._config.get("users", {}),
                "security_warning": _PPTP_SECURITY_WARNING,
            }
            self._save_config()

            self._logger.info("PPTP VPN配置完成: {} (注意: PPTP不安全)".format(server_ip))
            return {
                "status": "ok",
                "message": "PPTP VPN配置成功。" + _PPTP_SECURITY_WARNING,
                "data": self._config,
            }

        except Exception as e:
            self._logger.error("PPTP VPN配置失败: {}".format(e))
            return {"status": "error", "message": str(e)}

    def start(self) -> dict:
        """
        启动PPTP VPN服务

        Returns:
            包含操作结果的字典，包含安全警告
        """
        try:
            self._logger.warning(_PPTP_SECURITY_WARNING)

            pptpd_bin = shutil.which("pptpd")
            if not pptpd_bin:
                return {
                    "status": "error",
                    "message": "未找到pptpd命令，请先安装pptpd",
                }

            if not self._server_ip:
                return {"status": "error", "message": "请先配置PPTP VPN服务 (调用configure方法)"}

            # 启动pptpd进程
            result = subprocess.run(
                [pptpd_bin], capture_output=True, text=True, timeout=10
            )
            if result.returncode != 0:
                self._logger.error("pptpd启动失败: {}".format(result.stderr))
                return {
                    "status": "error",
                    "message": "pptpd启动失败: {}".format(result.stderr.strip()),
                }

            self._running = True
            self._config["running"] = True
            self._save_config()

            self._logger.warning("PPTP VPN服务已启动 (注意: PPTP协议不安全)")
            return {
                "status": "ok",
                "message": "PPTP VPN服务已启动。" + _PPTP_SECURITY_WARNING,
                "data": {"server_ip": self._server_ip, "subnet": self._subnet},
            }

        except subprocess.TimeoutExpired:
            return {"status": "error", "message": "pptpd启动超时"}
        except Exception as e:
            self._logger.error("PPTP VPN启动失败: {}".format(e))
            return {"status": "error", "message": str(e)}

    def stop(self) -> dict:
        """
        停止PPTP VPN服务

        Returns:
            包含操作结果的字典
        """
        try:
            subprocess.run(
                ["killall", "pptpd"], capture_output=True, text=True, timeout=5
            )

            self._running = False
            self._connections = []
            self._config["running"] = False
            self._save_config()

            self._logger.info("PPTP VPN服务已停止")
            return {"status": "ok", "message": "PPTP VPN服务已停止"}

        except Exception as e:
            self._logger.error("PPTP VPN停止失败: {}".format(e))
            return {"status": "error", "message": str(e)}

    def get_status(self) -> dict:
        """
        获取PPTP VPN服务状态

        Returns:
            包含服务状态信息的字典，附带安全警告
        """
        return {
            "status": "ok",
            "message": _PPTP_SECURITY_WARNING,
            "data": {
                "running": self._running,
                "server_ip": self._server_ip,
                "subnet": self._subnet,
                "user_count": len(self._users),
                "active_connections": len(self._connections),
                "security_warning": _PPTP_SECURITY_WARNING,
            },
        }

    def create_user(self, username, password) -> dict:
        """
        创建PPTP VPN用户

        Args:
            username: 用户名
            password: 用户密码 (MS-CHAP v2认证)

        Returns:
            包含操作结果的字典，附带安全警告
        """
        try:
            self._logger.warning(_PPTP_SECURITY_WARNING)

            if not self._server_ip:
                return {"status": "error", "message": "请先配置PPTP VPN服务"}

            if username in self._users:
                return {"status": "error", "message": "用户已存在: {}".format(username)}

            # 分配IP地址
            network = ipaddress.ip_network(self._subnet, strict=False)
            used_ips = set()
            for user_info in self._users.values():
                if user_info.get("assigned_ip"):
                    used_ips.add(ipaddress.ip_address(user_info["assigned_ip"]))
            assigned_ip = None
            for host in network.hosts():
                if host not in used_ips:
                    assigned_ip = str(host)
                    break
            if not assigned_ip:
                return {"status": "error", "message": "地址池已耗尽"}

            user_info = {
                "username": username,
                "assigned_ip": assigned_ip,
                "created_at": datetime.now().isoformat(),
            }

            self._users[username] = user_info
            self._config["users"] = self._users
            self._save_config()

            self._logger.info("创建PPTP VPN用户: {} (IP={})".format(username, assigned_ip))
            return {
                "status": "ok",
                "message": "用户创建成功。" + _PPTP_SECURITY_WARNING,
                "data": user_info,
            }

        except Exception as e:
            self._logger.error("创建PPTP VPN用户失败: {}".format(e))
            return {"status": "error", "message": str(e)}

    def delete_user(self, username) -> dict:
        """
        删除PPTP VPN用户

        Args:
            username: 要删除的用户名

        Returns:
            包含操作结果的字典
        """
        try:
            if username not in self._users:
                return {"status": "error", "message": "用户不存在: {}".format(username)}

            del self._users[username]
            self._config["users"] = self._users
            self._save_config()

            self._logger.info("删除PPTP VPN用户: {}".format(username))
            return {"status": "ok", "message": "用户已删除: {}".format(username)}

        except Exception as e:
            self._logger.error("删除PPTP VPN用户失败: {}".format(e))
            return {"status": "error", "message": str(e)}

    def list_users(self) -> list:
        """
        列出所有PPTP VPN用户

        Returns:
            用户信息列表
        """
        return [
            {
                "username": info["username"],
                "assigned_ip": info.get("assigned_ip"),
                "created_at": info.get("created_at"),
            }
            for info in self._users.values()
        ]

    def get_active_connections(self) -> list:
        """
        获取当前活跃的PPTP VPN连接

        Returns:
            活跃连接列表
        """
        if not self._running:
            return []

        try:
            # 检查pptpd进程和连接状态
            result = subprocess.run(
                ["ps", "aux"], capture_output=True, text=True, timeout=5
            )
            connections = []
            for line in result.stdout.splitlines():
                if "pptpd" in line:
                    connections.append({
                        "process": line.strip(),
                        "timestamp": datetime.now().isoformat(),
                    })
            return connections if connections else self._connections
        except Exception:
            return self._connections

    def get_stats(self) -> dict:
        """
        获取PPTP VPN服务统计信息

        Returns:
            包含统计数据的字典，附带安全警告
        """
        return {
            "status": "ok",
            "message": _PPTP_SECURITY_WARNING,
            "data": {
                "running": self._running,
                "total_users": len(self._users),
                "active_connections": len(self._connections),
                "subnet": self._subnet,
                "used_ips": len(self._users),
                "security_warning": _PPTP_SECURITY_WARNING,
            },
        }
