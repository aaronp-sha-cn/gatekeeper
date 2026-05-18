#!/bin/sh
# ============================================================
# GateKeeper - First Boot Configuration Script
# 由 systemd gatekeeper-setup.service 在首次启动后调用
# 完成安装后配置：SSL、Python venv、pip、数据库、服务启动
# ============================================================

# 不要使用 set -e，手动处理错误（避免静默退出）
set +e

mkdir -p /opt/gatekeeper/logs

LOG_FILE="/opt/gatekeeper/logs/first-start.log"
INSTALL_MARKER="/opt/gatekeeper/.install_pending"

# 输出函数：同时写日志文件、/dev/console、/dev/tty0、/dev/tty1
log() {
    _msg="[$(date '+%Y-%m-%d %H:%M:%S')] $1"
    echo "$_msg" >> "$LOG_FILE" 2>/dev/null
    echo "$_msg" > /dev/console 2>/dev/null
    echo "$_msg" > /dev/tty0 2>/dev/null
    echo "$_msg" > /dev/tty1 2>/dev/null
    # 使用 wall 广播到所有终端
    echo "GateKeeper: $1" | wall 2>/dev/null
    return 0
}

log "============================================"
log "GateKeeper first-boot configuration starting"
log "============================================"

# ============================================================
# 0. 检查 .install_pending 标记文件
#    如果不存在，说明安装已完成，跳过
# ============================================================
if [ ! -f "$INSTALL_MARKER" ]; then
    log "Installation already completed, skipping"
    exit 0
fi

export DEBIAN_FRONTEND=noninteractive

# ============================================================
# 1. 立即安装 python3-venv 和 python3-pip
#    这是后续所有操作的基础依赖
# ============================================================
log "[1/11] Installing python3-venv and python3-pip..."
DEBIAN_FRONTEND=noninteractive apt-get install -y python3-venv python3-pip 2>&1 | tee -a "$LOG_FILE" || {
    log "WARNING: python3-venv/pip install failed, will retry after apt update"
    DEBIAN_FRONTEND=noninteractive apt-get update 2>&1 | tee -a "$LOG_FILE" || true
    DEBIAN_FRONTEND=noninteractive apt-get install -y python3-venv python3-pip 2>&1 | tee -a "$LOG_FILE" || {
        log "ERROR: python3-venv/pip install failed after retry"
        exit 1
    }
}
log "  python3-venv and python3-pip installed"

# ============================================================
# 2. Set directory permissions
# ============================================================
log "[2/11] Setting directory permissions..."
mkdir -p /opt/gatekeeper/{data,logs,models,uploads,backups,data/certs}
chown -R root:root /opt/gatekeeper
chmod 755 /opt/gatekeeper
log "  Directory permissions set"

# ============================================================
# 3. Configure SSH access
# ============================================================
log "[3/11] Configuring SSH access..."

usermod -aG sudo admin 2>/dev/null || true

sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config 2>/dev/null || true
sed -i 's/^#*PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config 2>/dev/null || true

grep -q "^MaxAuthTries" /etc/ssh/sshd_config 2>/dev/null && \
    sed -i 's/^#*MaxAuthTries.*/MaxAuthTries 3/' /etc/ssh/sshd_config 2>/dev/null || \
    echo "MaxAuthTries 3" >> /etc/ssh/sshd_config 2>/dev/null || true

grep -q "^LoginGraceTime" /etc/ssh/sshd_config 2>/dev/null && \
    sed -i 's/^#*LoginGraceTime.*/LoginGraceTime 30/' /etc/ssh/sshd_config 2>/dev/null || \
    echo "LoginGraceTime 30" >> /etc/ssh/sshd_config 2>/dev/null || true

systemctl enable ssh 2>/dev/null || true
systemctl restart ssh 2>/dev/null || true

log "  SSH configured"

# ============================================================
# 4. Configure Junos-style CLI as default login shell
# ============================================================
log "[4/11] Configuring Junos-style CLI..."

cat > /opt/gatekeeper/scripts/junos-cli-wrapper.sh << 'WRAPPER_EOF'
#!/bin/bash
export PYTHONPATH=/opt/gatekeeper
source /opt/gatekeeper/venv/bin/activate 2>/dev/null || true
exec python3 /opt/gatekeeper/cli/junos_cli.py "$@"
WRAPPER_EOF

chmod +x /opt/gatekeeper/scripts/junos-cli-wrapper.sh

grep -q "junos-cli-wrapper" /etc/shells 2>/dev/null || echo "/opt/gatekeeper/scripts/junos-cli-wrapper.sh" >> /etc/shells

chsh -s /opt/gatekeeper/scripts/junos-cli-wrapper.sh admin 2>/dev/null || true

ln -sf /opt/gatekeeper/scripts/junos-cli-wrapper.sh /usr/local/bin/gatekeeper-cli 2>/dev/null || true
chmod +x /usr/local/bin/gatekeeper-cli 2>/dev/null || true

# Create symlinks for all CLI entry points
ln -sf /opt/gatekeeper/venv/bin/gk-cli /usr/local/bin/gk-cli 2>/dev/null || true
ln -sf /opt/gatekeeper/venv/bin/gk-junos /usr/local/bin/gk-junos 2>/dev/null || true
ln -sf /opt/gatekeeper/venv/bin/gk-cisco /usr/local/bin/gk-cisco 2>/dev/null || true
ln -sf /opt/gatekeeper/venv/bin/gatekeeper /usr/local/bin/gatekeeper 2>/dev/null || true

# Fallback: if pip install -e . failed, create wrapper scripts directly
if [ ! -f /opt/gatekeeper/venv/bin/gk-cli ]; then
    log "  pip install -e . may have failed, creating CLI wrapper scripts..."
    rm -f /usr/local/bin/gk-cli /usr/local/bin/gk-junos /usr/local/bin/gk-cisco /usr/local/bin/gatekeeper 2>/dev/null || true
    cat > /usr/local/bin/gk-cli << 'GKCLI_EOF'
#!/bin/bash
cd /opt/gatekeeper && /opt/gatekeeper/venv/bin/python -m cli.main "$@"
GKCLI_EOF
    chmod +x /usr/local/bin/gk-cli

    cat > /usr/local/bin/gatekeeper << 'GKEOF'
#!/bin/bash
cd /opt/gatekeeper && /opt/gatekeeper/venv/bin/python -m cli.main "$@"
GKEOF
    chmod +x /usr/local/bin/gatekeeper
else
    chmod +x /usr/local/bin/gk-cli /usr/local/bin/gk-junos /usr/local/bin/gk-cisco /usr/local/bin/gatekeeper 2>/dev/null || true
fi

log "  Junos CLI configured"

# ============================================================
# 5. Generate SSL certificate
# ============================================================
log "[5/11] Generating SSL certificate..."
CERT_DIR="/opt/gatekeeper/data/certs"
if [ ! -f "${CERT_DIR}/server.crt" ]; then
    openssl req -x509 -newkey rsa:2048 \
        -keyout "${CERT_DIR}/server.key" \
        -out "${CERT_DIR}/server.crt" \
        -days 365 \
        -nodes \
        -subj "/C=CN/ST=Beijing/L=Beijing/O=GateKeeper/CN=localhost" 2>&1 | tee -a "$LOG_FILE"
    if [ $? -eq 0 ]; then
        log "  SSL certificate generated"
    else
        log "  WARNING: SSL certificate generation failed"
    fi
else
    log "  SSL certificate already exists"
fi

# ============================================================
# 6. Create Python virtual environment
# ============================================================
log "[6/11] Creating Python virtual environment..."
cd /opt/gatekeeper || { log "ERROR: Cannot enter project directory"; exit 1; }

if [ ! -d "venv" ]; then
    python3 -m venv venv 2>&1 | tee -a "$LOG_FILE"
    if [ $? -ne 0 ]; then
        log "ERROR: Python venv creation failed"
        exit 1
    fi
    log "  Python venv created"
else
    log "  Python venv already exists"
fi

# ============================================================
# 7. Install Python dependencies
# ============================================================
log "[7/11] Installing Python dependencies..."

# Install system dependencies (build deps + network tools + security tools)
DEBIAN_FRONTEND=noninteractive apt-get install -y \
    build-essential \
    python3-dev \
    gcc g++ \
    libpcap-dev \
    libssl-dev \
    libffi-dev \
    libcap2-bin \
    ebtables \
    bridge-utils \
    tcpdump \
    nmap \
    iputils-ping \
    dnsutils \
    traceroute \
    fail2ban \
    ufw \
    dnsmasq \
    openssl \
    2>&1 | tee -a "$LOG_FILE" || true

/opt/gatekeeper/venv/bin/pip install --upgrade pip setuptools wheel --timeout 300 2>&1 | tee -a "$LOG_FILE"

PIP_SUCCESS=0
for i in 1 2 3; do
    log "  Installing dependencies (attempt $i/3)..."
    if /opt/gatekeeper/venv/bin/pip install -r /opt/gatekeeper/requirements.txt --timeout 600 --trusted-host pypi.org --trusted-host files.pythonhosted.org 2>&1 | tee -a "$LOG_FILE"; then
        PIP_SUCCESS=1
        log "  Python dependencies installed"
        break
    fi
    log "  pip install failed, installing core dependencies directly..."
    /opt/gatekeeper/venv/bin/pip install --timeout 600 --trusted-host pypi.org --trusted-host files.pythonhosted.org \
        flask \
        flask-login \
        flask-wtf \
        flask-limiter \
        werkzeug \
        markupsafe \
        sqlalchemy \
        scapy \
        scikit-learn \
        numpy \
        pandas \
        prompt-toolkit \
        psutil \
        cryptography \
        reportlab \
        apscheduler \
        schedule \
        paramiko \
        requests \
        email-validator \
        ldap3 \
        2>&1 | tee -a "$LOG_FILE"
    if [ $? -eq 0 ]; then
        PIP_SUCCESS=1
        log "  Core dependencies installed"
        break
    fi
    log "  pip install failed, retrying in 30s..."
    sleep 30
done

if [ $PIP_SUCCESS -eq 0 ]; then
    log "  ERROR: Core dependencies installation failed after 3 attempts"
fi

# Install project itself (register CLI entry points)
if [ $PIP_SUCCESS -eq 1 ]; then
    log "  Installing project CLI entry points..."
    cd /opt/gatekeeper && /opt/gatekeeper/venv/bin/pip install -e . --timeout 120 2>&1 | tee -a "$LOG_FILE" || true
fi

# ============================================================
# 8. Configure libpcap permissions
# ============================================================
if [ $PIP_SUCCESS -eq 1 ] || [ -f /opt/gatekeeper/venv/bin/python3 ]; then
    log "[8/11] Configuring network permissions..."

    DEBIAN_FRONTEND=noninteractive apt-get install -y libcap2-bin 2>&1 | tee -a "$LOG_FILE"

    if [ -f /opt/gatekeeper/venv/bin/python3 ]; then
        setcap 'cap_net_raw,cap_net_admin=eip' /opt/gatekeeper/venv/bin/python3 2>&1 | tee -a "$LOG_FILE" && \
            log "  Network permissions configured" || \
            log "  WARNING: setcap failed, scapy may require root"
    else
        log "  WARNING: venv python3 not found, skipping setcap"
    fi
else
    log "[8/11] Skipping network permissions (pip install failed)"
fi

# ============================================================
# 9. Security services (installed on-demand)
# ============================================================
log "[9/11] Security services setup..."
log "  Security services (ClamAV/Squid/ProFTPD/Postfix/Samba/mitmproxy) can be installed on-demand:"
log "  /opt/gatekeeper/scripts/install-security-services.sh"

# ============================================================
# 10. Initialize database
# ============================================================
if [ $PIP_SUCCESS -eq 1 ]; then
    log "[10/11] Initializing database..."
    PYTHONPATH=/opt/gatekeeper /opt/gatekeeper/venv/bin/python3 -c "
import sys, traceback
sys.path.insert(0, '/opt/gatekeeper')
try:
    from config.database import init_db
    init_db()
    print('Database initialized')
except Exception as e:
    print('ERROR: {}'.format(e), file=sys.stderr)
    traceback.print_exc()
    sys.exit(1)
" 2>&1 | tee -a "$LOG_FILE"
    if [ $? -eq 0 ]; then
        log "  Database initialized"
    else
        log "  WARNING: Database init failed (will retry on service start)"
    fi
else
    log "[10/11] Skipping database init (pip install failed)"
fi

# ============================================================
# 11. Configure systemd services and firewall
# ============================================================
log "[11/11] Configuring system services..."

# Main service
cat > /etc/systemd/system/gatekeeper.service << 'EOF'
[Unit]
Description=GateKeeper - AI Security Network Defense System
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=/opt/gatekeeper
Environment=PYTHONPATH=/opt/gatekeeper
EnvironmentFile=/opt/gatekeeper/.initial_credentials.env
ExecStart=/opt/gatekeeper/scripts/run-service.sh
Restart=on-failure
RestartSec=10
TimeoutStartSec=120
TimeoutStopSec=60
LimitNOFILE=65535
MemoryMax=4G
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

# Firewall rules
mkdir -p /etc/iptables
echo "iptables-persistent iptables-persistent/autosave_v4 boolean true" | debconf-set-selections 2>/dev/null || true
echo "iptables-persistent iptables-persistent/autosave_v6 boolean true" | debconf-set-selections 2>/dev/null || true
DEBIAN_FRONTEND=noninteractive apt-get install -y -o DPkg::Options::="--force-confdef" -o DPkg::Options::="--force-confold" iptables-persistent 2>&1 | tee -a "$LOG_FILE" || true

# Add ACCEPT rules first (before setting DROP policy)
iptables -I INPUT 1 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true
iptables -I INPUT 2 -i lo -j ACCEPT 2>/dev/null || true
iptables -A INPUT -p icmp --icmp-type echo-request -j ACCEPT 2>/dev/null || true
iptables -A INPUT -p icmp --icmp-type echo-reply -j ACCEPT 2>/dev/null || true
iptables -A INPUT -p tcp --dport 22 -j ACCEPT 2>/dev/null || true
iptables -A INPUT -p tcp --dport 8443 -j ACCEPT 2>/dev/null || true
iptables -A INPUT -p tcp --dport 8080 -j ACCEPT 2>/dev/null || true
iptables -P INPUT DROP 2>/dev/null || true
iptables -P FORWARD DROP 2>/dev/null || true
iptables -P OUTPUT ACCEPT 2>/dev/null || true
iptables-save > /etc/iptables/rules.v4 2>/dev/null || true

# Fail2Ban
mkdir -p /etc/fail2ban/filter.d
cat > /etc/fail2ban/jail.local << 'EOF'
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 5

[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 3

[gatekeeper]
enabled = true
port = https
filter = gatekeeper
logpath = /opt/gatekeeper/logs/security_audit.log
maxretry = 10
bantime = 7200
EOF

cat > /etc/fail2ban/filter.d/gatekeeper.conf << 'EOF'
[Definition]
failregex = .* LOGIN FAILED .* from <HOST>
ignoreregex =
EOF

# Log rotation
cat > /etc/logrotate.d/gatekeeper << 'EOF'
/opt/gatekeeper/logs/*.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    create 0640 root adm
}
EOF

log "  System services configured"

# ============================================================
# 12. Generate credentials, set permissions and start service
# ============================================================
log "[12/12] Generating credentials and starting service..."
chown -R root:root /opt/gatekeeper

if [ $PIP_SUCCESS -eq 1 ]; then
    # Generate random passwords
    SP_PASS=$(/opt/gatekeeper/venv/bin/python3 -c "import secrets; import string; a=string.ascii_letters+string.digits+'!@%&*'; print(''.join(secrets.choice(a) for _ in range(16)))" 2>/dev/null || echo "SpPass$(date +%s)!")
    ADMIN_PASS=$(/opt/gatekeeper/venv/bin/python3 -c "import secrets; import string; a=string.ascii_letters+string.digits+'!@%&*'; print(''.join(secrets.choice(a) for _ in range(16)))" 2>/dev/null || echo "AdminPass$(date +%s)!")
    ROOT_PASS=$(/opt/gatekeeper/venv/bin/python3 -c "import secrets; import string; a=string.ascii_letters+string.digits+'!@%&*'; print(''.join(secrets.choice(a) for _ in range(16)))" 2>/dev/null || echo "RootPass$(date +%s)!")
    (umask 077; cat > /opt/gatekeeper/.initial_credentials << CRED_EOF
admin-sp:${SP_PASS}
admin:${ADMIN_PASS}
root:${ROOT_PASS}
CRED_EOF
    )
    cat > /opt/gatekeeper/.initial_credentials.env << ENVEOF
GK_ADMIN_SP_PASSWORD=${SP_PASS}
GK_ADMIN_PASSWORD=${ADMIN_PASS}
ENVEOF
    chmod 600 /opt/gatekeeper/.initial_credentials.env

    # Start the service
    systemctl daemon-reload 2>/dev/null || true
    systemctl enable gatekeeper.service 2>/dev/null || true
    systemctl start gatekeeper.service 2>/dev/null || true

    # Remove marker only after everything succeeded
    rm -f "$INSTALL_MARKER"

    log ""
    log "============================================"
    log "GateKeeper setup complete!"
    log "============================================"
    log ""
    log "Web Panel: https://$(hostname -I 2>/dev/null | awk '{print $1}' || echo 'localhost'):8443"
    log ""
    log "=== INITIAL CREDENTIALS (save these now!) ==="
    log "admin-sp : ${SP_PASS}"
    log "admin    : ${ADMIN_PASS}"
    log "root     : ${ROOT_PASS}"
    log ""
    log "Credentials also saved to: /opt/gatekeeper/.initial_credentials"
    log ""
    log "Management commands:"
    log "  systemctl status gatekeeper"
    log "  journalctl -u gatekeeper -f"
    log "============================================"
else
    log ""
    log "============================================"
    log "ERROR: Installation incomplete, check logs"
    log "  cat $LOG_FILE"
    log "============================================"
fi
