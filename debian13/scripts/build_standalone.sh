#!/bin/bash
# ============================================================
# GateKeeper - Debian 13 独立安装包构建脚本
# 生成 tar.gz 安装包，可在已安装的 Debian 13 系统上直接安装
# ============================================================

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info()  { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
log_step()  { echo -e "${BLUE}[STEP]${NC} $1"; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
BUILD_DIR="${PROJECT_DIR}/build"
PKG_NAME="gatekeeper"
PKG_VERSION="1.0.4"
PKG_FILE="${BUILD_DIR}/${PKG_NAME}-${PKG_VERSION}-debian13.tar.gz"

log_step "[1/4] 创建构建目录..."
rm -rf "${BUILD_DIR}"
mkdir -p "${BUILD_DIR}/opt/${PKG_NAME}"
mkdir -p "${BUILD_DIR}/usr/lib/systemd/system"
mkdir -p "${BUILD_DIR}/etc/${PKG_NAME}"

log_step "[2/4] 复制项目文件..."

# 复制Python源码
rsync -av \
    --exclude='iso_build' \
    --exclude='venv' \
    --exclude='.git' \
    --exclude='__pycache__' \
    --exclude='*.pyc' \
    --exclude='*.iso' \
    --exclude='*.zip' \
    --exclude='build' \
    --exclude='.uploads' \
    --exclude='logs/*.log' \
    --exclude='tests' \
    "${PROJECT_DIR}/" "${BUILD_DIR}/opt/${PKG_NAME}/"

# 设置脚本可执行权限
chmod +x "${BUILD_DIR}/opt/${PKG_NAME}/scripts/"*.sh 2>/dev/null || true

log_step "[3/4] 创建systemd服务文件..."

# 创建gatekeeper.service
cat > "${BUILD_DIR}/usr/lib/systemd/system/gatekeeper.service" << 'EOF'
[Unit]
Description=GateKeeper - AI Security Network Defense System
After=network.target network-online.target
Wants=network-online.target
Documentation=https://github.com/gatekeeper

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=/opt/gatekeeper
ExecStart=/opt/gatekeeper/scripts/run-service.sh
ExecStop=/opt/gatekeeper/scripts/stop.sh
Restart=on-failure
RestartSec=10
TimeoutStartSec=120
StandardOutput=journal
StandardError=journal
SyslogIdentifier=gatekeeper

# 安全加固
NoNewPrivileges=false
ProtectSystem=false
ProtectHome=false

[Install]
WantedBy=multi-user.target
EOF

# 创建gatekeeper-setup.service (首次启动)
cat > "${BUILD_DIR}/usr/lib/systemd/system/gatekeeper-setup.service" << 'EOF'
[Unit]
Description=GateKeeper First Start Setup
After=network.target
ConditionPathExists=!/etc/gatekeeper/.setup_complete

[Service]
Type=oneshot
User=root
ExecStart=/opt/gatekeeper/scripts/first-start.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

log_step "[4/4] 创建安装脚本..."

# 创建install.sh
cat > "${BUILD_DIR}/install.sh" << 'INSTALL_EOF'
#!/bin/bash
# ============================================================
# GateKeeper 安装脚本 - Debian 13
# ============================================================
set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}  GateKeeper 安装程序 - Debian 13${NC}"
echo -e "${GREEN}========================================${NC}"

# 检查root权限
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}请使用 root 权限运行安装脚本${NC}"
    echo "  sudo bash install.sh"
    exit 1
fi

# 检测系统
if [ ! -f /etc/debian_version ]; then
    echo -e "${RED}此安装包仅支持 Debian 系统${NC}"
    exit 1
fi

DEBIAN_VER=$(cat /etc/debian_version | cut -d. -f1)
echo -e "${GREEN}检测到 Debian ${DEBIAN_VER}${NC}"

# 获取脚本所在目录
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo ""
echo "[1/6] 安装系统依赖..."
apt-get update -qq
apt-get install -y -qq \
    python3 \
    python3-pip \
    python3-venv \
    python3-dev \
    git \
    curl \
    wget \
    net-tools \
    iproute2 \
    iptables \
    ebtables \
    bridge-utils \
    libpcap-dev \
    libssl-dev \
    libffi-dev \
    libcap2-bin \
    tcpdump \
    nmap \
    iputils-ping \
    dnsutils \
    traceroute \
    sudo \
    systemd \
    fail2ban \
    dnsmasq \
    genisoimage \
    2>/dev/null || true

echo "[2/6] 复制程序文件..."
cp -r "${SCRIPT_DIR}/opt/gatekeeper" /opt/gatekeeper
chmod +x /opt/gatekeeper/scripts/*.sh

echo "[3/6] 安装systemd服务..."
cp "${SCRIPT_DIR}/usr/lib/systemd/system/gatekeeper.service" /usr/lib/systemd/system/
cp "${SCRIPT_DIR}/usr/lib/systemd/system/gatekeeper-setup.service" /usr/lib/systemd/system/
systemctl daemon-reload
systemctl enable gatekeeper
systemctl enable gatekeeper-setup

echo "[4/6] 创建管理用户..."
if ! id -u admin > /dev/null 2>&1; then
    useradd -m -s /bin/bash -G sudo admin 2>/dev/null || true
    echo "admin:Gk@Ad#2026!Admin" | chpasswd
    echo -e "${GREEN}管理用户已创建: admin（初始密码请查看 /opt/gatekeeper/.initial_credentials）${NC}"
else
    echo "管理用户 admin 已存在，跳过创建"
fi

echo "[5/6] 配置SSH..."
sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config 2>/dev/null || true
sed -i 's/^#*PermitRootLogin.*/PermitRootLogin prohibit-password/' /etc/ssh/sshd_config 2>/dev/null || true
systemctl restart ssh 2>/dev/null || true

echo "[6/6] 配置系统内核参数..."
# 启用IP转发（网关模式需要）
echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
echo "net.bridge.bridge-nf-call-iptables=1" >> /etc/sysctl.conf
sysctl -p 2>/dev/null || true

# 加载br_netfilter模块
modprobe br_netfilter 2>/dev/null || true
echo "br_netfilter" >> /etc/modules-load.d/gatekeeper.conf 2>/dev/null || true

echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}  安装完成！${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
echo "  Web面板:  https://$(hostname -I 2>/dev/null | awk '{print $1}'):8443"
echo "  用户名:   admin"
echo "  密码:     ****（请查看 /opt/gatekeeper/.initial_credentials）"
echo "  SSH:      ssh admin@$(hostname -I 2>/dev/null | awk '{print $1}')"
echo ""
echo "  启动命令: systemctl start gatekeeper"
echo "  查看日志: journalctl -u gatekeeper -f"
echo ""
echo "  首次启动将自动执行初始化（约2-3分钟）"
echo ""
INSTALL_EOF

chmod +x "${BUILD_DIR}/install.sh"

# 创建uninstall.sh
cat > "${BUILD_DIR}/uninstall.sh" << 'UNINSTALL_EOF'
#!/bin/bash
# GateKeeper 卸载脚本
set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}请使用 root 权限运行${NC}"
    exit 1
fi

echo -e "${YELLOW}正在卸载 GateKeeper...${NC}"

systemctl stop gatekeeper 2>/dev/null || true
systemctl disable gatekeeper 2>/dev/null || true
systemctl stop gatekeeper-setup 2>/dev/null || true
systemctl disable gatekeeper-setup 2>/dev/null || true

rm -f /usr/lib/systemd/system/gatekeeper.service
rm -f /usr/lib/systemd/system/gatekeeper-setup.service
systemctl daemon-reload

rm -rf /opt/gatekeeper
rm -rf /etc/gatekeeper

echo -e "${GREEN}GateKeeper 已卸载${NC}"
UNINSTALL_EOF

chmod +x "${BUILD_DIR}/uninstall.sh"

# 打包
log_step "创建安装包..."
cd "${BUILD_DIR}"
tar czf "${PKG_FILE}" \
    opt/ \
    usr/ \
    install.sh \
    uninstall.sh

# 清理临时文件
rm -rf "${BUILD_DIR}/opt" "${BUILD_DIR}/usr"

PKG_SIZE=$(du -h "${PKG_FILE}" | cut -f1)
PKG_MD5=$(md5sum "${PKG_FILE}" | cut -d' ' -f1)

echo ""
echo -e "${GREEN}============================================${NC}"
echo -e "${GREEN}  安装包构建完成！${NC}"
echo -e "${GREEN}============================================${NC}"
echo ""
echo "  文件: ${PKG_FILE}"
echo "  大小: ${PKG_SIZE}"
echo "  MD5:  ${PKG_MD5}"
echo ""
echo "  安装方法:"
echo "    1. 将安装包传输到 Debian 13 系统"
echo "    2. tar xzf gatekeeper-1.0.4-debian13.tar.gz"
echo "    3. sudo bash install.sh"
echo ""
echo "  卸载方法:"
echo "    sudo bash uninstall.sh"
echo ""
