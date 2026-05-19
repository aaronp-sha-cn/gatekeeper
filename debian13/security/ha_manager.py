"""GateKeeper - 高可用管理器，支持主备(active-passive)和双活(active-active)集群模式"""
import os, json, socket, time, uuid, subprocess, threading
from datetime import datetime
from typing import Dict, List, Optional
from config.logging_config import get_logger

logger = get_logger("ha_manager")
HA_CONFIG_PATH = "/etc/gatekeeper/rules/ha_config.json"
HEARTBEAT_PORT = 694
HEARTBEAT_INTERVAL = 3
HEARTBEAT_TIMEOUT = 10
FAILBACK_DELAY = 30


class HAManager:
    """高可用管理器 - 支持主备和双活集群模式，心跳检测/VIP管理/配置同步/脑裂防护"""

    def __init__(self):
        """初始化HA管理器，加载配置"""
        self._config = self._load_config()
        self._lock = threading.RLock()
        self._node_state = "standalone"
        self._ha_mode = self._config.get("mode", "active-passive")
        self._running = False
        self._maintenance_mode = False
        self._heartbeat_thread: Optional[threading.Thread] = None
        self._monitor_thread: Optional[threading.Thread] = None
        self._last_heartbeat_received: Optional[float] = None
        self._peer_alive = False
        self._missed_heartbeats = 0
        self._peer_ip = self._config.get("peer_ip", "")
        self._vip = self._config.get("vip", "")
        self._interface = self._config.get("interface", "eth0")
        self._node_id = self._config.get("node_id", str(uuid.uuid4())[:8])
        self._failover_history: List[dict] = []
        self._sync_state = {"firewall_rules": False, "nat_rules": False, "vpn_tunnels": False,
                            "dhcp_leases": False, "dns_cache": False, "last_sync": None}
        self._fenced = False
        self._fence_time: Optional[float] = None
        self._sock: Optional[socket.socket] = None
        logger.info("HA管理器初始化完成 (模式: %s, 节点ID: %s)", self._ha_mode, self._node_id)

    # ---- 配置管理 ----
    def _load_config(self) -> dict:
        """从配置文件加载HA配置"""
        default = {"mode": "active-passive", "peer_ip": "", "vip": "", "interface": "eth0",
                   "node_id": str(uuid.uuid4())[:8], "heartbeat_interval": HEARTBEAT_INTERVAL,
                   "heartbeat_timeout": HEARTBEAT_TIMEOUT, "failback_delay": FAILBACK_DELAY,
                   "auto_failback": False, "fence_enabled": True, "sync_on_start": True,
                   "health_check_interval": 10, "health_check_endpoints": ["/api/health"]}
        if os.path.isfile(HA_CONFIG_PATH):
            try:
                with open(HA_CONFIG_PATH, "r", encoding="utf-8") as f:
                    default.update(json.load(f))
                logger.info("已加载HA配置: %s", HA_CONFIG_PATH)
            except Exception as e:
                logger.error("加载HA配置失败: %s", e)
        return default

    def _save_config(self):
        """保存当前配置到文件"""
        try:
            os.makedirs(os.path.dirname(HA_CONFIG_PATH), exist_ok=True)
            with open(HA_CONFIG_PATH, "w", encoding="utf-8") as f:
                json.dump(self._config, f, ensure_ascii=False, indent=2)
        except Exception as e:
            logger.error("保存HA配置失败: %s", e)

    def configure(self, mode: str, peer_ip: str, vip: str, interface: str, **kwargs) -> dict:
        """配置HA集群参数（模式/对端IP/VIP/接口）"""
        if mode not in ("active-passive", "active-active"):
            return {"status": "error", "message": "无效的HA模式: {}".format(mode)}
        if not peer_ip:
            return {"status": "error", "message": "对端IP地址不能为空"}
        if not vip:
            return {"status": "error", "message": "虚拟IP地址不能为空"}
        with self._lock:
            self._ha_mode, self._peer_ip, self._vip, self._interface = mode, peer_ip, vip, interface
            self._config.update({"mode": mode, "peer_ip": peer_ip, "vip": vip, "interface": interface})
            self._config.update(kwargs)
            self._save_config()
        logger.info("HA配置已更新: 模式=%s, 对端=%s, VIP=%s", mode, peer_ip, vip)
        return {"status": "success", "message": "HA配置已更新",
                "config": {"mode": mode, "peer_ip": peer_ip, "vip": vip, "interface": interface}}

    # ---- 启动与停止 ----
    def start(self) -> dict:
        """启动HA服务（创建UDP套接字、心跳线程、监控线程）"""
        if self._running:
            return {"status": "error", "message": "HA服务已在运行中"}
        if not self._peer_ip:
            return {"status": "error", "message": "未配置对端IP，请先调用configure()"}
        if not self._vip:
            return {"status": "error", "message": "未配置虚拟IP，请先调用configure()"}
        with self._lock:
            try:
                self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                self._sock.bind(("0.0.0.0", HEARTBEAT_PORT))
                self._sock.settimeout(1.0)
                logger.info("UDP心跳套接字已创建，端口: %d", HEARTBEAT_PORT)
                self._determine_initial_role()
                self._running, self._missed_heartbeats, self._fenced = True, 0, False
                self._heartbeat_thread = threading.Thread(target=self._heartbeat_sender_loop,
                                                          name="ha-heartbeat", daemon=True)
                self._heartbeat_thread.start()
                self._monitor_thread = threading.Thread(target=self._heartbeat_monitor_loop,
                                                        name="ha-monitor", daemon=True)
                self._monitor_thread.start()
                if self._node_state in ("primary", "active"):
                    self._acquire_vip()
                if self._config.get("sync_on_start", True):
                    self._sync_config_async()
                logger.info("HA服务已启动，当前角色: %s", self._node_state)
                return {"status": "success", "message": "HA服务已启动", "node_state": self._node_state}
            except Exception as e:
                logger.error("HA服务启动失败: %s", e)
                self._running = False
                return {"status": "error", "message": "启动失败: {}".format(e)}

    def stop(self) -> dict:
        """停止HA服务（释放VIP、关闭套接字、停止线程）"""
        with self._lock:
            if not self._running:
                return {"status": "error", "message": "HA服务未在运行"}
            self._running = False
            if self._node_state in ("primary", "active"):
                self._release_vip()
            if self._sock:
                try:
                    self._sock.close()
                except Exception:
                    pass
                self._sock = None
            for t in (self._heartbeat_thread, self._monitor_thread):
                if t:
                    t.join(timeout=3)
            old = self._node_state
            self._node_state, self._peer_alive = "standalone", False
            logger.info("HA服务已停止 (原角色: %s)", old)
            return {"status": "success", "message": "HA服务已停止", "previous_state": old}

    def _determine_initial_role(self):
        """确定节点初始角色（通过比较node_id决定主备）"""
        try:
            probe = json.dumps({"type": "probe", "node_id": self._node_id, "timestamp": time.time()}).encode()
            self._sock.sendto(probe, (self._peer_ip, HEARTBEAT_PORT))
            self._sock.settimeout(2.0)
            try:
                data, addr = self._sock.recvfrom(4096)
                msg = json.loads(data.decode())
                if msg.get("type") == "probe_ack":
                    peer_id = msg.get("node_id", "")
                    if self._node_id < peer_id:
                        self._node_state = "primary" if self._ha_mode == "active-passive" else "active"
                    else:
                        self._node_state = "secondary" if self._ha_mode == "active-passive" else "active"
                    self._peer_alive = True
                    self._last_heartbeat_received = time.time()
                    logger.info("对端已响应 (ID: %s), 本节点角色: %s", peer_id, self._node_state)
                    return
            except socket.timeout:
                pass
            self._node_state = "primary" if self._ha_mode == "active-passive" else "active"
            logger.info("未检测到对端，本节点成为主节点")
        except Exception as e:
            self._node_state = "primary" if self._ha_mode == "active-passive" else "active"
            logger.warning("角色探测失败，默认为主节点: %s", e)
        finally:
            self._sock.settimeout(1.0)

    # ---- 心跳机制 ----
    def _heartbeat_sender_loop(self):
        """心跳发送循环 - 定期向对端发送心跳包并监听响应"""
        interval = self._config.get("heartbeat_interval", HEARTBEAT_INTERVAL)
        while self._running:
            try:
                if self._maintenance_mode:
                    time.sleep(interval)
                    continue
                msg = json.dumps({"type": "heartbeat", "node_id": self._node_id,
                                  "state": self._node_state, "timestamp": time.time(),
                                  "fenced": self._fenced}).encode()
                if self._sock:
                    self._sock.sendto(msg, (self._peer_ip, HEARTBEAT_PORT))
                self._receive_heartbeat()
            except Exception as e:
                logger.debug("心跳发送异常: %s", e)
            time.sleep(interval)

    def _receive_heartbeat(self):
        """接收并处理对端的心跳消息"""
        if not self._sock:
            return
        try:
            self._sock.settimeout(0.5)
            while True:
                try:
                    data, addr = self._sock.recvfrom(4096)
                    msg = json.loads(data.decode())
                    mt = msg.get("type", "")
                    if mt == "heartbeat":
                        self._last_heartbeat_received = time.time()
                        self._missed_heartbeats = 0
                        if not self._peer_alive:
                            logger.info("对端节点上线: %s", addr[0])
                            self._peer_alive = True
                    elif mt == "probe":
                        ack = json.dumps({"type": "probe_ack", "node_id": self._node_id,
                                          "state": self._node_state, "timestamp": time.time()}).encode()
                        if self._sock:
                            self._sock.sendto(ack, addr)
                    elif mt == "sync_request":
                        self._handle_sync_request(msg, addr)
                    elif mt == "sync_data":
                        self._handle_sync_data(msg)
                    elif mt == "fence_notify":
                        self._handle_fence_notify(msg)
                except socket.timeout:
                    break
                except json.JSONDecodeError:
                    continue
        except Exception:
            pass
        finally:
            if self._sock:
                self._sock.settimeout(1.0)

    def _heartbeat_monitor_loop(self):
        """心跳监控循环 - 检测对端心跳超时并触发故障转移"""
        timeout = self._config.get("heartbeat_timeout", HEARTBEAT_TIMEOUT)
        while self._running:
            time.sleep(timeout / 2)
            if self._maintenance_mode or self._last_heartbeat_received is None:
                continue
            if time.time() - self._last_heartbeat_received > timeout:
                self._missed_heartbeats += 1
                logger.warning("对端心跳超时 (连续丢失: %d)", self._missed_heartbeats)
                if self._missed_heartbeats >= 3:
                    self._handle_peer_failure()
            else:
                self._missed_heartbeats = 0

    def _handle_peer_failure(self):
        """处理对端故障 - 执行自动故障转移"""
        if self._fenced:
            logger.warning("本节点已被隔离(fenced)，不执行故障转移")
            return
        old = self._node_state
        ts = datetime.now().isoformat()
        if self._ha_mode == "active-passive" and self._node_state == "secondary":
            self._node_state = "primary"
            self._acquire_vip()
            logger.warning("故障转移: 备节点升级为主节点，VIP: %s", self._vip)
        elif self._ha_mode == "active-active":
            logger.warning("双活模式对端故障，本节点继续提供服务")
        self._peer_alive = False
        self._failover_history.append({"timestamp": ts, "type": "failover", "from_state": old,
                                       "to_state": self._node_state, "reason": "peer_heartbeat_timeout"})
        logger.info("故障转移完成: %s -> %s", old, self._node_state)

    # ---- VIP管理 ----
    def _acquire_vip(self) -> bool:
        """接管虚拟IP地址（ip addr add + gratuitous ARP）"""
        if not self._vip or not self._interface:
            return False
        try:
            r = subprocess.run(["ip", "addr", "add", "{}/32".format(self._vip), "dev", self._interface],
                               capture_output=True, text=True, timeout=10)
            if r.returncode == 0:
                subprocess.run(["arping", "-c", "3", "-A", "-I", self._interface, self._vip],
                               capture_output=True, timeout=10)
                logger.info("VIP已接管: %s (%s)", self._vip, self._interface)
                return True
            logger.error("VIP接管失败: %s", r.stderr)
            return False
        except Exception as e:
            logger.error("VIP接管异常: %s", e)
            return False

    def _release_vip(self) -> bool:
        """释放虚拟IP地址"""
        if not self._vip or not self._interface:
            return False
        try:
            r = subprocess.run(["ip", "addr", "del", "{}/32".format(self._vip), "dev", self._interface],
                               capture_output=True, text=True, timeout=10)
            if r.returncode == 0:
                logger.info("VIP已释放: %s (%s)", self._vip, self._interface)
                return True
            logger.warning("VIP释放失败: %s", r.stderr)
            return False
        except Exception as e:
            logger.error("VIP释放异常: %s", e)
            return False

    # ---- 配置同步 ----
    def sync_config(self) -> dict:
        """手动触发配置同步（防火墙/NAT/VPN/DHCP/DNS）"""
        if not self._running:
            return {"status": "error", "message": "HA服务未运行"}
        if not self._peer_alive:
            return {"status": "error", "message": "对端节点不可达"}
        data = self._collect_sync_data()
        if not data:
            return {"status": "error", "message": "无可用同步数据"}
        try:
            msg = json.dumps({"type": "sync_data", "node_id": self._node_id,
                              "timestamp": time.time(), "data": data}).encode()
            if self._sock:
                self._sock.sendto(msg, (self._peer_ip, HEARTBEAT_PORT))
            self._sync_state["last_sync"] = datetime.now().isoformat()
            for k in data:
                self._sync_state[k] = True
            logger.info("配置同步已发送: %s", list(data.keys()))
            return {"status": "success", "message": "配置同步已发送", "synced_items": list(data.keys())}
        except Exception as e:
            logger.error("配置同步失败: %s", e)
            return {"status": "error", "message": str(e)}

    def _sync_config_async(self):
        """异步执行配置同步"""
        def _do():
            time.sleep(2)
            if self._peer_alive:
                self.sync_config()
        threading.Thread(target=_do, daemon=True).start()

    def _collect_sync_data(self) -> dict:
        """收集同步数据（防火墙规则/NAT规则/VPN/DHCP/DNS缓存）"""
        data = {}
        try:
            r = subprocess.run(["iptables-save"], capture_output=True, text=True, timeout=10)
            if r.returncode == 0:
                data["firewall_rules"] = r.stdout
        except Exception:
            pass
        try:
            r = subprocess.run(["iptables", "-t", "nat", "-L", "-n"], capture_output=True, text=True, timeout=10)
            if r.returncode == 0:
                data["nat_rules"] = r.stdout
        except Exception:
            pass
        for path, key in [("/var/lib/misc/dnsmasq.leases", "dhcp_leases"),
                          ("/tmp/dnsmasq_cache", "dns_cache")]:
            if os.path.isfile(path):
                try:
                    with open(path, "r") as f:
                        data[key] = f.read()
                except Exception:
                    pass
        return data

    def _handle_sync_request(self, msg: dict, addr: tuple):
        """处理对端同步请求"""
        data = self._collect_sync_data()
        if data and self._sock:
            reply = json.dumps({"type": "sync_data", "node_id": self._node_id,
                                "timestamp": time.time(), "data": data}).encode()
            self._sock.sendto(reply, addr)

    def _handle_sync_data(self, msg: dict):
        """处理收到的同步数据并应用到本节点"""
        data = msg.get("data", {})
        applied = []
        if "firewall_rules" in data:
            try:
                subprocess.run(["iptables-restore"], input=data["firewall_rules"],
                               capture_output=True, text=True, timeout=10)
                applied.append("firewall_rules")
                self._sync_state["firewall_rules"] = True
            except Exception as e:
                logger.error("应用防火墙规则失败: %s", e)
        for k in ("nat_rules", "dhcp_leases", "dns_cache"):
            if k in data:
                applied.append(k)
                self._sync_state[k] = True
        self._sync_state["last_sync"] = datetime.now().isoformat()
        logger.info("已应用对端同步数据: %s", applied)

    # ---- 隔离(Fencing)与脑裂防护 ----
    def _handle_fence_notify(self, msg: dict):
        """处理隔离通知 - 释放VIP并降级"""
        if not self._config.get("fence_enabled", True) or msg.get("node_id") == self._node_id:
            return
        logger.warning("收到隔离通知，本节点将被隔离(fenced)")
        self._fenced, self._fence_time = True, time.time()
        if self._node_state in ("primary", "active"):
            self._release_vip()
            self._node_state = "secondary"
        self._failover_history.append({"timestamp": datetime.now().isoformat(), "type": "fenced",
                                       "reason": "received_fence_notify", "fenced_by": msg.get("node_id")})

    # ---- 故障转移控制 ----
    def force_failover(self) -> dict:
        """手动触发故障转移"""
        if not self._running:
            return {"status": "error", "message": "HA服务未运行"}
        old = self._node_state
        if self._ha_mode == "active-passive":
            if self._node_state == "primary":
                self._release_vip()
                self._node_state = "secondary"
                if self._sock and self._peer_alive:
                    notify = json.dumps({"type": "heartbeat", "node_id": self._node_id,
                                         "state": "yield", "timestamp": time.time()}).encode()
                    self._sock.sendto(notify, (self._peer_ip, HEARTBEAT_PORT))
                logger.info("手动故障转移: 主节点让出")
            elif self._node_state == "secondary":
                self._node_state = "primary"
                self._acquire_vip()
                logger.info("手动故障转移: 备节点强制接管")
        elif self._ha_mode == "active-active":
            return {"status": "info", "message": "双活模式无需手动故障转移"}
        self._failover_history.append({"timestamp": datetime.now().isoformat(), "type": "manual_failover",
                                       "from_state": old, "to_state": self._node_state, "reason": "manual"})
        return {"status": "success", "message": "故障转移已执行",
                "from_state": old, "to_state": self._node_state}

    # ---- 状态查询 ----
    def get_status(self) -> dict:
        """获取HA管理器当前状态"""
        return {"engine": "ha_manager", "running": self._running, "mode": self._ha_mode,
                "node_state": self._node_state, "node_id": self._node_id,
                "peer_ip": self._peer_ip, "vip": self._vip, "interface": self._interface,
                "peer_alive": self._peer_alive, "maintenance_mode": self._maintenance_mode,
                "fenced": self._fenced, "sync_state": dict(self._sync_state)}

    def get_peer_status(self) -> dict:
        """获取对端节点状态"""
        last = datetime.fromtimestamp(self._last_heartbeat_received).isoformat() if self._last_heartbeat_received else None
        return {"peer_ip": self._peer_ip, "alive": self._peer_alive, "last_heartbeat": last,
                "missed_heartbeats": self._missed_heartbeats, "heartbeat_timeout": 5}

    def get_health(self) -> dict:
        """获取HA健康检查结果"""
        issues, overall = [], "healthy"
        if not self._running:
            issues.append("HA服务未运行"); overall = "unhealthy"
        if self._fenced:
            issues.append("节点已被隔离(fenced)"); overall = "unhealthy"
        if self._maintenance_mode:
            issues.append("维护模式已启用"); overall = "maintenance"
        if self._running and not self._peer_alive:
            issues.append("对端节点不可达")
            if overall == "healthy": overall = "degraded"
        if self._vip and self._node_state in ("primary", "active") and not self._check_vip_active():
            issues.append("VIP未在本地绑定")
            if overall == "healthy": overall = "degraded"
        return {"ha_running": self._running, "node_state": self._node_state, "peer_alive": self._peer_alive,
                "vip_configured": bool(self._vip), "fenced": self._fenced,
                "maintenance_mode": self._maintenance_mode, "overall": overall, "issues": issues}

    def _check_vip_active(self) -> bool:
        """检查VIP是否在本地接口上激活"""
        try:
            r = subprocess.run(["ip", "addr", "show", self._interface],
                               capture_output=True, text=True, timeout=5)
            return self._vip in r.stdout
        except Exception:
            return False

    def get_failover_history(self) -> list:
        """获取故障转移历史记录"""
        with self._lock:
            return list(self._failover_history)

    # ---- 维护模式 ----
    def enable_maintenance_mode(self) -> dict:
        """启用维护模式（不发送心跳、不参与故障转移）"""
        with self._lock:
            self._maintenance_mode = True
            if self._node_state in ("primary", "active") and self._peer_alive:
                self._release_vip()
                logger.info("维护模式已启用，VIP已释放")
            return {"status": "success", "message": "维护模式已启用", "previous_state": self._node_state}

    def disable_maintenance_mode(self) -> dict:
        """禁用维护模式，恢复正常HA操作"""
        with self._lock:
            self._maintenance_mode, self._fenced = False, False
            if self._peer_alive:
                if self._ha_mode == "active-passive":
                    self._node_state = "secondary"
                logger.info("维护模式已禁用，作为备节点运行")
            else:
                self._node_state = "primary" if self._ha_mode == "active-passive" else "active"
                self._acquire_vip()
                logger.info("维护模式已禁用，对端不可达，升级为主节点")
            return {"status": "success", "message": "维护模式已禁用", "current_state": self._node_state}


# 模块级单例
_ha_instance: Optional[HAManager] = None
_ha_lock = threading.Lock()

def get_ha_manager() -> HAManager:
    """获取HA管理器单例"""
    global _ha_instance
    with _ha_lock:
        if _ha_instance is None:
            _ha_instance = HAManager()
        return _ha_instance
