#!/bin/sh
# ============================================================
# GateKeeper - Post-install Script (Installation Phase)
# Executed during Debian late_command
# Only configures systemd service; complex tasks deferred to first boot
# ============================================================

export DEBIAN_FRONTEND=noninteractive
set +e

LOG_FILE="/opt/gatekeeper/logs/postinstall.log"
mkdir -p /opt/gatekeeper/logs

log() {
    echo "$1" | tee -a "$LOG_FILE"
}

log "[GateKeeper] Post-install starting..."
log "[GateKeeper] Configuring first-boot service..."

# Update apt in chroot (sources.list should be configured by late-command)
apt-get update 2>/dev/null || true

# Ensure bash is available (needed by first-start.sh)
apt-get install -y bash 2>/dev/null || log "WARNING: bash install failed, using sh"

# Ensure first-start.sh is executable
chmod +x /opt/gatekeeper/scripts/first-start.sh 2>/dev/null || true

# Ensure systemd directories exist
mkdir -p /etc/systemd/system
mkdir -p /etc/systemd/system/multi-user.target.wants

# Configure first-boot service (oneshot)
cat > /etc/systemd/system/gatekeeper-setup.service << 'EOF'
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
EOF

# Enable service
ln -sf /etc/systemd/system/gatekeeper-setup.service /etc/systemd/system/multi-user.target.wants/gatekeeper-setup.service

# Create install marker so first-start.sh knows to run
mkdir -p /opt/gatekeeper
touch /opt/gatekeeper/.install_pending

log "[GateKeeper] First-boot service configured"
log "[GateKeeper] Post-install complete"
