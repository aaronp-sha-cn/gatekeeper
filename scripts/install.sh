#!/bin/bash
# ============================================================
# GateKeeper - 自动安装脚本
# 适用于 Debian 12 (Bookworm)
# ============================================================

set -e

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 日志函数
log_info()    { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn()    { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error()   { echo -e "${RED}[ERROR]${NC} $1"; }
log_step()    { echo -e "${BLUE}[STEP]${NC} $1"; }

# 检查是否为root用户
if [ "$EUID" -ne 0 ]; then
    log_error "请使用root权限运行此脚本"
    echo "用法: sudo ./scripts/install.sh"
    exit 1
fi

# 检查操作系统
log_step "检查操作系统..."
if [ ! -f /etc/debian_version ]; then
    log_error "此脚本仅适用于Debian系统"
    exit 1
fi

DEBIAN_VERSION=$(cat /etc/debian_version | cut -d. -f1)
if [ "$DEBIAN_VERSION" -lt 12 ]; then
    log_warn "推荐使用 Debian 12，当前版本: $(cat /etc/debian_version)"
fi
log_info "操作系统: Debian $(cat /etc/debian_version)"

# ============================================================
# 1. 更新系统
# ============================================================
log_step "更新系统软件包..."
apt-get update -qq
apt-get upgrade -y -qq

# ============================================================
# 2. 安装系统依赖
# ============================================================
log_step "安装系统依赖..."

# 基础工具
apt-get install -y -qq \
    build-essential \
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
    libpcap-dev \
    libssl-dev \
    libffi-dev

# 网络工具
apt-get install -y -qq \
    tcpdump \
    nmap \
    iputils-ping \
    dnsutils \
    traceroute \
    whois

# 数据库（可选，默认使用SQLite）
log_info "如需PostgreSQL支持，请手动安装: apt-get install postgresql postgresql-server-dev-all"

# ============================================================
# 3. 创建Python虚拟环境
# ============================================================
log_step "创建Python虚拟环境..."
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [ ! -d "${PROJECT_DIR}/venv" ]; then
    python3 -m venv "${PROJECT_DIR}/venv"
    log_info "虚拟环境已创建: ${PROJECT_DIR}/venv"
else
    log_info "虚拟环境已存在，跳过创建"
fi

# 激活虚拟环境
source "${PROJECT_DIR}/venv/bin/activate"

# ============================================================
# 4. 安装Python依赖
# ============================================================
log_step "安装Python依赖..."
pip install --upgrade pip setuptools wheel
pip install -r "${PROJECT_DIR}/requirements.txt"

# ============================================================
# 5. 配置libpcap权限
# ============================================================
log_step "配置网络抓包权限..."
setcap 'cap_net_raw,cap_net_admin=eip' "$(readlink -f "$(which python3)")" 2>/dev/null || {
    log_warn "无法设置Python抓包权限，数据包捕获可能需要root权限"
    log_warn "可手动执行: sudo setcap 'cap_net_raw,cap_net_admin=eip' $(which python3)"
}

# ============================================================
# 6. 创建必要目录
# ============================================================
log_step "创建数据目录..."
mkdir -p "${PROJECT_DIR}/data"
mkdir -p "${PROJECT_DIR}/logs"
mkdir -p "${PROJECT_DIR}/models"
mkdir -p "${PROJECT_DIR}/uploads"
mkdir -p "${PROJECT_DIR}/backups"
mkdir -p "${PROJECT_DIR}/data/certs"

# ============================================================
# 7. 生成自签名SSL证书
# ============================================================
log_step "生成自签名SSL证书..."
CERT_DIR="${PROJECT_DIR}/data/certs"
if [ ! -f "${CERT_DIR}/server.crt" ] || [ ! -f "${CERT_DIR}/server.key" ]; then
    openssl req -x509 -newkey rsa:2048 \
        -keyout "${CERT_DIR}/server.key" \
        -out "${CERT_DIR}/server.crt" \
        -days 365 \
        -nodes \
        -subj "/C=CN/ST=Beijing/L=Beijing/O=GateKeeper/CN=localhost" \
        2>/dev/null
    log_info "SSL证书已生成"
else
    log_info "SSL证书已存在，跳过"
fi

# ============================================================
# 8. 初始化数据库
# ============================================================
log_step "初始化数据库..."
cd "${PROJECT_DIR}"
python3 -c "
from config.database import init_db, check_connection
init_db()
ok, msg = check_connection()
print(f'数据库: {msg}')
"

# ============================================================
# 9. 创建默认管理员
# ============================================================
log_step "创建默认管理员..."
python3 -c "
from core.database import db_manager
from core.models import User, UserRole
from utils.crypto import hash_password

import secrets, string
# 生成随机强密码（16位，包含大小写字母、数字、特殊字符）
alphabet = string.ascii_letters + string.digits + '!@%&*'
random_password = ''.join(secrets.choice(alphabet) for _ in range(16))

with db_manager.get_session() as session:
    admin = session.query(User).filter_by(username='admin').first()
    if not admin:
        admin = User(
            username='admin',
            email='admin@gatekeeper.local',
            password_hash=hash_password(random_password),
            role=UserRole.ADMIN,
            is_active=True,
            must_change_password=True,  # 强制首次登录修改密码
        )
        session.add(admin)
        print('默认管理员已创建')
        print('用户名: admin')
        print('密码: {}'.format(random_password))
        print('注意：首次登录需要修改密码')
        # 将密码保存到文件供参考
        import os
        cred_file = os.path.join(os.path.expanduser('~'), '.gatekeeper_admin_credentials')
        with open(cred_file, 'w') as f:
            f.write('admin:{}\n'.format(random_password))
        os.chmod(cred_file, 0o600)
        print('密码已保存到: {} (权限 600)'.format(cred_file))
    else:
        print('默认管理员已存在')
"

# ============================================================
# 10. 配置systemd服务（可选）
# ============================================================
log_step "配置systemd服务..."
cat > /etc/systemd/system/gatekeeper.service << EOF
[Unit]
Description=GateKeeper - AI安全网络防御系统
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=${PROJECT_DIR}
ExecStart=${PROJECT_DIR}/venv/bin/python3 -m core.app
Restart=on-failure
RestartSec=10
Environment=PYTHONPATH=${PROJECT_DIR}

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
log_info "systemd服务已配置"

# ============================================================
# 完成
# ============================================================
echo ""
echo "============================================"
log_info "GateKeeper 安装完成!"
echo "============================================"
echo ""
echo "项目目录: ${PROJECT_DIR}"
echo "虚拟环境: ${PROJECT_DIR}/venv"
echo "SSL证书:  ${CERT_DIR}/server.crt"
echo ""
echo "启动方式:"
echo "  1. 直接启动:  cd ${PROJECT_DIR} && ./scripts/start.sh"
echo "  2. 系统服务:  systemctl start gatekeeper"
echo "  3. CLI工具:   cd ${PROJECT_DIR} && ./venv/bin/python3 -m cli.main"
echo ""
echo "Web管理面板: https://localhost:8443"
echo "默认账号:     admin / Gk@Ad#2026!Admin"
echo ""
log_warn "请立即修改默认管理员密码!"
echo "============================================"
