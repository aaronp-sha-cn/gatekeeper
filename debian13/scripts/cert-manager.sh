#!/bin/bash
# ============================================================
# GateKeeper - SSL证书自动管理脚本
# 支持 Let's Encrypt (certbot) 和自签名证书
# ============================================================
set -euo pipefail

# ============================================================
# 配置（可通过环境变量覆盖）
# ============================================================
CERT_DOMAIN="${GK_CERT_DOMAIN:-localhost}"
CERT_EMAIL="${GK_CERT_EMAIL:-}"
CERT_MODE="${GK_CERT_MODE:-self-signed}"
CERT_WEBROOT="${GK_CERT_WEBROOT:-/var/www/html}"
CERT_STANDALONE_PORT="${GK_CERT_STANDALONE_PORT:-8888}"
CERT_DAYS_BEFORE_RENEW="${GK_CERT_DAYS_BEFORE_RENEW:-30}"

# 证书输出路径
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
CERT_DIR="${PROJECT_DIR}/data/certs"
CERT_KEY_FILE="${CERT_DIR}/server.key"
CERT_CERT_FILE="${CERT_DIR}/server.crt"
CERT_CHAIN_FILE="${CERT_DIR}/chain.pem"
CERT_FULLCHAIN_FILE="${CERT_DIR}/fullchain.pem"

# 颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info()  { echo -e "${GREEN}[INFO]${NC}  $(date '+%Y-%m-%d %H:%M:%S') - $*"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC}  $(date '+%Y-%m-%d %H:%M:%S') - $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $(date '+%Y-%m-%d %H:%M:%S') - $*"; }

# ============================================================
# 工具函数
# ============================================================
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "此脚本需要 root 权限运行"
        exit 1
    fi
}

ensure_cert_dir() {
    mkdir -p "$CERT_DIR"
    chmod 700 "$CERT_DIR"
}

cert_exists() {
    [[ -f "$CERT_CERT_FILE" ]] && [[ -f "$CERT_KEY_FILE" ]]
}

cert_expires_soon() {
    if ! command -v openssl &>/dev/null; then
        log_warn "openssl 未安装，无法检查证书过期时间"
        return 0
    fi

    if [[ ! -f "$CERT_CERT_FILE" ]]; then
        return 0
    fi

    local expiry_date
    expiry_date=$(openssl x509 -in "$CERT_CERT_FILE" -noout -enddate 2>/dev/null | cut -d= -f2)
    if [[ -z "$expiry_date" ]]; then
        return 0
    fi

    local expiry_epoch now_epoch days_left
    expiry_epoch=$(date -d "$expiry_date" +%s 2>/dev/null || echo "0")
    now_epoch=$(date +%s)
    days_left=$(( (expiry_epoch - now_epoch) / 86400 ))

    if [[ $days_left -lt $CERT_DAYS_BEFORE_RENEW ]]; then
        log_info "证书将在 ${days_left} 天后过期，需要续签"
        return 0
    else
        log_info "证书还有 ${days_left} 天过期，无需续签"
        return 1
    fi
}

# ============================================================
# 自签名证书生成
# ============================================================
generate_self_signed() {
    log_info "生成自签名 SSL 证书..."

    ensure_cert_dir

    if ! command -v openssl &>/dev/null; then
        log_error "openssl 未安装，无法生成自签名证书"
        exit 1
    fi

    # 生成 RSA 私钥 (2048位)
    openssl genrsa -out "$CERT_KEY_FILE" 2048 2>/dev/null

    # 生成自签名证书 (有效期10年)
    openssl req -new -x509 \
        -key "$CERT_KEY_FILE" \
        -out "$CERT_CERT_FILE" \
        -days 3650 \
        -subj "/C=CN/ST=Beijing/L=Beijing/O=GateKeeper/CN=${CERT_DOMAIN}" \
        2>/dev/null

    # 复制为 fullchain（自签名证书场景下 chain 等同于 cert）
    cp "$CERT_CERT_FILE" "$CERT_FULLCHAIN_FILE"
    cp "$CERT_CERT_FILE" "$CERT_CHAIN_FILE"

    chmod 600 "$CERT_KEY_FILE"
    chmod 644 "$CERT_CERT_FILE"

    log_info "自签名证书已生成:"
    log_info "  证书: ${CERT_CERT_FILE}"
    log_info "  私钥: ${CERT_KEY_FILE}"
    log_info "  域名: ${CERT_DOMAIN}"
}

# ============================================================
# Let's Encrypt 证书管理
# ============================================================
check_certbot() {
    if command -v certbot &>/dev/null; then
        return 0
    fi
    return 1
}

install_certbot() {
    log_info "尝试安装 certbot..."

    if command -v apt-get &>/dev/null; then
        apt-get update -qq
        apt-get install -y -qq certbot 2>/dev/null
    elif command -v yum &>/dev/null; then
        yum install -y -q certbot 2>/dev/null
    elif command -v apk &>/dev/null; then
        apk add --no-progress certbot 2>/dev/null
    else
        log_error "无法自动安装 certbot，请手动安装"
        return 1
    fi

    if check_certbot; then
        log_info "certbot 安装成功"
        return 0
    else
        log_error "certbot 安装失败"
        return 1
    fi
}

obtain_letsencrypt_standalone() {
    log_info "使用 standalone 模式获取 Let's Encrypt 证书..."

    ensure_cert_dir

    certbot certonly \
        --standalone \
        --preferred-challenges http \
        --http-01-port "$CERT_STANDALONE_PORT" \
        -d "$CERT_DOMAIN" \
        --email "$CERT_EMAIL" \
        --agree-tos \
        --non-interactive \
        --keep-until-expiring \
        --cert-name "gatekeeper" \
        2>&1

    if [[ $? -ne 0 ]]; then
        log_error "Let's Encrypt 证书获取失败"
        return 1
    fi

    # 复制证书到项目目录
    _copy_letsencrypt_certs
}

obtain_letsencrypt_webroot() {
    log_info "使用 webroot 模式获取 Let's Encrypt 证书..."

    ensure_cert_dir
    mkdir -p "$CERT_WEBROOT"

    certbot certonly \
        --webroot \
        -w "$CERT_WEBROOT" \
        -d "$CERT_DOMAIN" \
        --email "$CERT_EMAIL" \
        --agree-tos \
        --non-interactive \
        --keep-until-expiring \
        --cert-name "gatekeeper" \
        2>&1

    if [[ $? -ne 0 ]]; then
        log_error "Let's Encrypt 证书获取失败"
        return 1
    fi

    _copy_letsencrypt_certs
}

_copy_letsencrypt_certs() {
    local le_live_dir="/etc/letsencrypt/live/gatekeeper"

    if [[ -d "$le_live_dir" ]]; then
        cp "${le_live_dir}/privkey.pem" "$CERT_KEY_FILE"
        cp "${le_live_dir}/cert.pem" "$CERT_CERT_FILE"
        cp "${le_live_dir}/chain.pem" "$CERT_CHAIN_FILE"
        cp "${le_live_dir}/fullchain.pem" "$CERT_FULLCHAIN_FILE"
        chmod 600 "$CERT_KEY_FILE"
        chmod 644 "$CERT_CERT_FILE"
        log_info "Let's Encrypt 证书已复制到: ${CERT_DIR}"
    else
        log_error "Let's Encrypt 证书目录不存在: ${le_live_dir}"
        return 1
    fi
}

renew_letsencrypt() {
    log_info "续签 Let's Encrypt 证书..."

    certbot renew --non-interactive 2>&1

    if [[ $? -eq 0 ]]; then
        _copy_letsencrypt_certs
        log_info "证书续签成功"
    else
        log_warn "证书续签失败或无需续签"
    fi
}

# ============================================================
# Cron 自动续签
# ============================================================
install_cron() {
    log_info "安装证书自动续签 cron 任务..."

    local cron_cmd="0 3 * * * ${SCRIPT_DIR}/cert-manager.sh renew >> /var/log/gatekeeper-cert-renew.log 2>&1"

    # 检查是否已存在
    if crontab -l 2>/dev/null | grep -q "cert-manager.sh renew"; then
        log_info "cron 任务已存在，跳过安装"
        return 0
    fi

    (crontab -l 2>/dev/null; echo "$cron_cmd") | crontab -
    log_info "cron 任务已安装: 每天凌晨 3:00 自动续签"
}

remove_cron() {
    log_info "移除证书自动续签 cron 任务..."

    crontab -l 2>/dev/null | grep -v "cert-manager.sh renew" | crontab -
    log_info "cron 任务已移除"
}

# ============================================================
# 主逻辑
# ============================================================
obtain_certificate() {
    if [[ "$CERT_MODE" == "letsencrypt" ]]; then
        # Let's Encrypt 模式
        if ! check_certbot; then
            log_warn "certbot 未安装，尝试自动安装..."
            if ! install_certbot; then
                log_warn "certbot 安装失败，回退到自签名证书"
                generate_self_signed
                return 0
            fi
        fi

        if [[ -z "$CERT_EMAIL" ]]; then
            log_warn "GK_CERT_EMAIL 未设置，Let's Encrypt 需要邮箱地址"
            log_warn "回退到自签名证书"
            generate_self_signed
            return 0
        fi

        if [[ "$CERT_DOMAIN" == "localhost" || "$CERT_DOMAIN" == "127.0.0.1" ]]; then
            log_warn "域名 ${CERT_DOMAIN} 不支持 Let's Encrypt，回退到自签名证书"
            generate_self_signed
            return 0
        fi

        # 尝试 standalone 模式
        if ! obtain_letsencrypt_standalone; then
            log_warn "standalone 模式失败，尝试 webroot 模式..."
            if ! obtain_letsencrypt_webroot; then
                log_warn "webroot 模式也失败，回退到自签名证书"
                generate_self_signed
                return 0
            fi
        fi

        # 安装自动续签
        install_cron

    else
        # 自签名模式
        generate_self_signed
    fi
}

renew_certificate() {
    if [[ "$CERT_MODE" == "letsencrypt" ]] && check_certbot; then
        if cert_expires_soon; then
            renew_letsencrypt
        fi
    else
        if cert_expires_soon; then
            log_info "重新生成自签名证书..."
            generate_self_signed
        fi
    fi
}

show_status() {
    echo "============================================"
    echo "  GateKeeper SSL 证书状态"
    echo "============================================"
    echo "  模式:       ${CERT_MODE}"
    echo "  域名:       ${CERT_DOMAIN}"
    echo "  证书路径:   ${CERT_CERT_FILE}"
    echo "  私钥路径:   ${CERT_KEY_FILE}"

    if cert_exists; then
        echo "  证书状态:   已存在"
        if command -v openssl &>/dev/null; then
            echo ""
            openssl x509 -in "$CERT_CERT_FILE" -noout -subject -dates -issuer 2>/dev/null | sed 's/^/  /'
        fi
    else
        echo "  证书状态:   不存在"
    fi

    if [[ "$CERT_MODE" == "letsencrypt" ]]; then
        echo ""
        if check_certbot; then
            echo "  certbot:    已安装 ($(certbot --version 2>/dev/null | head -1))"
        else
            echo "  certbot:    未安装"
        fi

        if crontab -l 2>/dev/null | grep -q "cert-manager.sh renew"; then
            echo "  自动续签:   已启用"
        else
            echo "  自动续签:   未启用"
        fi
    fi
    echo "============================================"
}

usage() {
    echo "用法: $0 {obtain|renew|cron-install|cron-remove|status|help}"
    echo ""
    echo "命令:"
    echo "  obtain        获取SSL证书（Let's Encrypt 或自签名）"
    echo "  renew         续签证书（仅在即将过期时执行）"
    echo "  cron-install  安装自动续签 cron 任务"
    echo "  cron-remove   移除自动续签 cron 任务"
    echo "  status        显示证书状态"
    echo "  help          显示帮助信息"
    echo ""
    echo "环境变量:"
    echo "  GK_CERT_DOMAIN       域名 (默认: localhost)"
    echo "  GK_CERT_EMAIL        Let's Encrypt 通知邮箱"
    echo "  GK_CERT_MODE         模式: letsencrypt / self-signed (默认: self-signed)"
    echo "  GK_CERT_WEBROOT      webroot 路径 (默认: /var/www/html)"
    echo "  GK_CERT_STANDALONE_PORT  standalone 端口 (默认: 8888)"
    echo "  GK_CERT_DAYS_BEFORE_RENEW  续签天数阈值 (默认: 30)"
}

# ============================================================
# 入口
# ============================================================
case "${1:-help}" in
    obtain)
        check_root
        obtain_certificate
        ;;
    renew)
        check_root
        renew_certificate
        ;;
    cron-install)
        check_root
        install_cron
        ;;
    cron-remove)
        check_root
        remove_cron
        ;;
    status)
        show_status
        ;;
    help|--help|-h)
        usage
        ;;
    *)
        log_error "未知命令: $1"
        usage
        exit 1
        ;;
esac
