#!/bin/sh
# ============================================================
# GateKeeper - Post-install Script (安装阶段)
# 由 late-command.sh 在 chroot 中执行
# 运行环境：chroot（/target），systemd 不可用
# ============================================================
#
# 关键修复说明：
# - shebang 使用 #!/bin/sh（chroot 中可能没有 bash）
# - 先 apt-get update（使用 late-command.sh 配置的 archive.debian.org 源）
# - 安装 bash（供 first-start.sh 使用）
# - 创建 gatekeeper-setup.service（Type=oneshot）
# - 使用 ln -sf 启用服务（不使用 systemctl enable，chroot 中 systemd 不可用）
# - 创建 .install_pending 标记文件（供 first-start.sh 检查）
# ============================================================

export DEBIAN_FRONTEND=noninteractive

LOG_FILE="/opt/gatekeeper/logs/postinstall.log"
mkdir -p /opt/gatekeeper/logs

log() {
    echo "$1" | tee -a "$LOG_FILE"
}

log "[GateKeeper] ============================================"
log "[GateKeeper] Post-install 开始执行..."
log "[GateKeeper] ============================================"

# ============================================================
# 1. 更新 apt 软件包列表
#    此时 sources.list 已由 late-command.sh 配置为 archive.debian.org
# ============================================================
log "[GateKeeper] [1] 更新 apt 软件包列表..."
apt-get update 2>&1 | tee -a "$LOG_FILE"
if [ $? -ne 0 ]; then
    log "[GateKeeper] [1] WARNING: apt-get update 失败，但继续执行"
fi

# ============================================================
# 2. 安装 bash
#    first-start.sh 需要 bash 来执行（检测到 bash 可用后 exec /bin/bash）
# ============================================================
log "[GateKeeper] [2] 安装 bash..."
apt-get install -y bash 2>&1 | tee -a "$LOG_FILE"
if [ $? -ne 0 ]; then
    log "[GateKeeper] [2] WARNING: bash 安装失败，first-start.sh 将使用 sh"
else
    log "[GateKeeper] [2] bash 安装成功"
fi

# ============================================================
# 3. 确保 first-start.sh 可执行
# ============================================================
log "[GateKeeper] [3] 设置脚本权限..."
chmod +x /opt/gatekeeper/scripts/first-start.sh 2>/dev/null || true
log "[GateKeeper] [3] 脚本权限已设置"

# ============================================================
# 4. 创建 gatekeeper-setup.service（Type=oneshot）
#    该服务在首次启动时执行 first-start.sh
# ============================================================
log "[GateKeeper] [4] 创建 systemd 首次启动服务..."

mkdir -p /etc/systemd/system
mkdir -p /etc/systemd/system/multi-user.target.wants

cat > /etc/systemd/system/gatekeeper-setup.service << 'SERVICE_EOF'
[Unit]
Description=GateKeeper - First Time Setup
After=network-online.target network.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/opt/gatekeeper/scripts/first-start.sh
TimeoutStartSec=900
StandardOutput=journal+console
StandardError=journal+console

[Install]
WantedBy=multi-user.target
SERVICE_EOF

log "[GateKeeper] [4] 服务文件已创建"

# ============================================================
# 5. 启用服务（使用 ln -sf，不使用 systemctl enable）
#    chroot 环境中 systemd 不可用，必须手动创建符号链接
# ============================================================
log "[GateKeeper] [5] 启用 gatekeeper-setup.service..."
ln -sf /etc/systemd/system/gatekeeper-setup.service \
    /etc/systemd/system/multi-user.target.wants/gatekeeper-setup.service

# 验证符号链接是否创建成功
if [ -L /etc/systemd/system/multi-user.target.wants/gatekeeper-setup.service ]; then
    log "[GateKeeper] [5] 服务已启用（符号链接创建成功）"
else
    log "[GateKeeper] [5] WARNING: 服务启用失败（符号链接未创建）"
fi

# ============================================================
# 6. 创建 .install_pending 标记文件
#    first-start.sh 检查此文件判断是否需要执行安装
# ============================================================
log "[GateKeeper] [6] 创建安装标记..."
mkdir -p /opt/gatekeeper
touch /opt/gatekeeper/.install_pending
log "[GateKeeper] [6] 安装标记已创建: /opt/gatekeeper/.install_pending"

log "[GateKeeper] ============================================"
log "[GateKeeper] Post-install 执行完成"
log "[GateKeeper] ============================================"
