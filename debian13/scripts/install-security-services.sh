#!/bin/bash
# GateKeeper - 安全服务按需安装脚本
# 用法: ./install-security-services.sh [all|clamav|squid|proftpd|postfix|samba|mitmproxy]
set -euo pipefail

LOG_FILE="/opt/gatekeeper/logs/install-security-services.log"
mkdir -p /opt/gatekeeper/logs

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

SERVICES=("${@:-all}")

install_clamav() {
    log "安装 ClamAV 抗病毒引擎..."
    apt-get install -y clamav clamav-daemon 2>&1 | tee -a "$LOG_FILE" && \
        log "  ClamAV 安装完成" || log "  WARNING: ClamAV 安装失败"
    freshclam 2>&1 | tee -a "$LOG_FILE" || true
}

install_squid() {
    log "安装 Squid HTTP 代理 + c-icap..."
    apt-get install -y squid c-icap 2>&1 | tee -a "$LOG_FILE" && \
        log "  Squid + c-icap 安装完成" || log "  WARNING: Squid 安装失败"
}

install_proftpd() {
    log "安装 ProFTPD FTP 服务器..."
    apt-get install -y proftpd-basic 2>&1 | tee -a "$LOG_FILE" && \
        log "  ProFTPD 安装完成" || log "  WARNING: ProFTPD 安装失败"
}

install_postfix() {
    log "安装 Postfix SMTP + amavisd-new..."
    apt-get install -y postfix amavisd-new 2>&1 | tee -a "$LOG_FILE" && \
        log "  Postfix + amavisd-new 安装完成" || log "  WARNING: Postfix 安装失败"
}

install_samba() {
    log "安装 Samba SMB/CIFS..."
    apt-get install -y samba 2>&1 | tee -a "$LOG_FILE" && \
        log "  Samba 安装完成" || log "  WARNING: Samba 安装失败"
}

install_mitmproxy() {
    log "安装 mitmproxy SSL/TLS 检查..."
    apt-get install -y mitmproxy 2>&1 | tee -a "$LOG_FILE" && \
        log "  mitmproxy 安装完成" || log "  WARNING: mitmproxy 安装失败"
}

install_all() {
    log "安装所有安全服务..."
    install_clamav
    install_squid
    install_proftpd
    install_postfix
    install_samba
    install_mitmproxy
    log "所有安全服务安装完成"
}

log "============================================"
log "GateKeeper 安全服务安装"
log "============================================"

case "${SERVICES[0]}" in
    all) install_all ;;
    clamav) install_clamav ;;
    squid) install_squid ;;
    proftpd) install_proftpd ;;
    postfix) install_postfix ;;
    samba) install_samba ;;
    mitmproxy) install_mitmproxy ;;
    *)
        echo "用法: $0 [all|clamav|squid|proftpd|postfix|samba|mitmproxy]"
        echo "  all       - 安装所有安全服务"
        echo "  clamav    - ClamAV 抗病毒引擎"
        echo "  squid     - Squid HTTP 代理"
        echo "  proftpd   - ProFTPD FTP 服务器"
        echo "  postfix   - Postfix SMTP 邮件"
        echo "  samba     - Samba 文件共享"
        echo "  mitmproxy - mitmproxy SSL/TLS 检查"
        exit 1
        ;;
esac
