#!/bin/bash
# ============================================================
# GateKeeper - ISO构建脚本 (无挂载版本)
# 使用7z/xorriso直接提取ISO内容，无需mount权限
# ============================================================

set -e

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info()  { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
log_step()  { echo -e "${BLUE}[STEP]${NC} $1"; }

# ============================================================
# 配置变量
# ============================================================
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
BUILD_DIR="${PROJECT_DIR}/iso_build/build"
ISO_NAME="gatekeeper-1.0.4-debian10.iso"

# Debian ISO镜像源列表（按优先级排序）
DEBIAN_MIRRORS=(
    "https://mirrors.tuna.tsinghua.edu.cn/debian-cd/current/amd64/iso-cd/debian-12.5.0-amd64-netinst.iso"
    "https://mirrors.ustc.edu.cn/debian-cd/current/amd64/iso-cd/debian-12.5.0-amd64-netinst.iso"
    "https://mirrors.aliyun.com/debian-cd/current/amd64/iso-cd/debian-12.5.0-amd64-netinst.iso"
)

# ============================================================
# 1. 安装ISO构建工具
# ============================================================
log_step "[1/7] 安装ISO构建工具..."
apt-get update -qq 2>/dev/null || true
apt-get install -y -qq \
    xorriso \
    isolinux \
    syslinux-utils \
    squashfs-tools \
    dosfstools \
    cpio \
    gzip \
    wget \
    rsync \
    p7zip-full \
    genisoimage 2>/dev/null || true

log_info "构建工具安装完成"

# ============================================================
# 2. 下载Debian基础ISO（多镜像源尝试）
# ============================================================
log_step "[2/7] 下载Debian 12基础ISO..."
DEBIAN_ISO="${BUILD_DIR}/debian-base.iso"
mkdir -p "${BUILD_DIR}"

if [ -f "${DEBIAN_ISO}" ]; then
    log_info "基础ISO已存在: ${DEBIAN_ISO}"
else
    DOWNLOADED=0
    for mirror in "${DEBIAN_MIRRORS[@]}"; do
        log_info "尝试镜像源: ${mirror}"
        if wget -q --show-progress --timeout=60 -O "${DEBIAN_ISO}" "${mirror}" 2>/dev/null; then
            DOWNLOADED=1
            log_info "下载成功!"
            break
        else
            log_warn "镜像源不可用，尝试下一个..."
            rm -f "${DEBIAN_ISO}"
        fi
    done
    
    if [ $DOWNLOADED -eq 0 ]; then
        log_error "所有镜像源均下载失败!"
        log_info "请手动下载Debian 12 netinst ISO到: ${DEBIAN_ISO}"
        exit 1
    fi
fi

# ============================================================
# 3. 使用7z提取ISO内容（无需mount）
# ============================================================
log_step "[3/7] 提取ISO内容..."
EXTRACT_DIR="${BUILD_DIR}/extract"

rm -rf "${EXTRACT_DIR}"
mkdir -p "${EXTRACT_DIR}"

# 使用7z提取ISO内容
if command -v 7z &> /dev/null; then
    7z x "${DEBIAN_ISO}" -o"${EXTRACT_DIR}" -y > /dev/null 2>&1
    log_info "ISO内容提取完成 (使用7z)"
else
    # 使用xorriso提取
    xorriso -osirrox on -indev "${DEBIAN_ISO}" -extract / "${EXTRACT_DIR}" 2>/dev/null || true
    log_info "ISO内容提取完成 (使用xorriso)"
fi

# 确保关键目录存在
mkdir -p "${EXTRACT_DIR}/isolinux"
mkdir -p "${EXTRACT_DIR}/install.amd"

# ============================================================
# 4. 准备GateKeeper安装包
# ============================================================
log_step "[4/7] 准备GateKeeper安装包..."
GK_PKG_DIR="${BUILD_DIR}/gatekeeper-pkg"
mkdir -p "${GK_PKG_DIR}/opt/gatekeeper"

# 复制项目文件（排除iso_build目录避免循环）
rsync -av --exclude='iso_build' --exclude='venv' --exclude='.git' --exclude='__pycache__' --exclude='*.pyc' "${PROJECT_DIR}/" "${GK_PKG_DIR}/opt/gatekeeper/" 2>/dev/null || \
    (cp -r "${PROJECT_DIR}/"* "${GK_PKG_DIR}/opt/gatekeeper/" 2>/dev/null || true)

# 排除不必要的文件
rm -rf "${GK_PKG_DIR}/opt/gatekeeper/venv" 2>/dev/null || true
rm -rf "${GK_PKG_DIR}/opt/gatekeeper/.git" 2>/dev/null || true
rm -rf "${GK_PKG_DIR}/opt/gatekeeper/iso_build" 2>/dev/null || true
find "${GK_PKG_DIR}" -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true

# 复制postinstall脚本
cp "${SCRIPT_DIR}/postinstall.sh" "${GK_PKG_DIR}/opt/gatekeeper/scripts/postinstall.sh"
chmod +x "${GK_PKG_DIR}/opt/gatekeeper/scripts/"*.sh

# 创建安装包tarball
cd "${BUILD_DIR}"
tar czf gatekeeper.tar.gz -C "${GK_PKG_DIR}" .
mv gatekeeper.tar.gz "${EXTRACT_DIR}/"

log_info "安装包准备完成"

# ============================================================
# 5. 集成preseed自动化配置
# ============================================================
log_step "[5/7] 集成preseed自动化配置..."
cp "${SCRIPT_DIR}/preseed.cfg" "${EXTRACT_DIR}/preseed.cfg"

# 复制late-command脚本
cp "${SCRIPT_DIR}/late-command.sh" "${EXTRACT_DIR}/late-command.sh" 2>/dev/null || true

# 修改isolinux配置以支持自动安装
if [ -f "${EXTRACT_DIR}/isolinux/isolinux.cfg" ]; then
    cat > "${EXTRACT_DIR}/isolinux/isolinux.cfg" << 'ISOLINUX_CFG'
DEFAULT auto
PROMPT 0
TIMEOUT 10

LABEL auto
    kernel /install.amd/vmlinuz
    append initrd=/install.amd/initrd.gz auto=true file=/cdrom/preseed.cfg priority=critical debconf/priority=critical -- quiet

LABEL manual
    kernel /install.amd/vmlinuz
    append initrd=/install.amd/initrd.gz -- quiet
ISOLINUX_CFG
    log_info "isolinux配置已更新"
fi

# 修改GRUB配置（如果存在）
if [ -d "${EXTRACT_DIR}/boot/grub" ]; then
    cat > "${EXTRACT_DIR}/boot/grub/grub.cfg" << 'GRUB_CFG'
set timeout=10
set default=0

menuentry "GateKeeper - 自动安装 (推荐)" {
    linux /install.amd/vmlinuz auto=true file=/cdrom/preseed.cfg priority=critical quiet
    initrd /install.amd/initrd.gz
}

menuentry "GateKeeper - 手动安装" {
    linux /install.amd/vmlinuz quiet
    initrd /install.amd/initrd.gz
}
GRUB_CFG
    log_info "GRUB配置已更新"
fi

# ============================================================
# 6. 重新生成ISO
# ============================================================
log_step "[6/7] 生成GateKeeper ISO..."
OUTPUT_ISO="${PROJECT_DIR}/${ISO_NAME}"

# 使用genisoimage或xorriso生成ISO
cd "${EXTRACT_DIR}"

if command -v genisoimage &> /dev/null; then
    # 使用genisoimage
    genisoimage \
        -r -V "GATEKEEPER" \
        -o "${OUTPUT_ISO}" \
        -J -joliet-long \
        -b isolinux/isolinux.bin \
        -c isolinux/boot.cat \
        -no-emul-boot \
        -boot-load-size 4 \
        -boot-info-table \
        -eltorito-alt-boot \
        -e boot/grub/efi.img \
        -no-emul-boot \
        . 2>/dev/null || true
    log_info "ISO生成完成 (使用genisoimage)"
else
    # 使用xorriso
    xorriso -as mkisofs \
        -r \
        -V "GATEKEEPER" \
        -o "${OUTPUT_ISO}" \
        -J -joliet-long \
        -b isolinux/isolinux.bin \
        -c isolinux/boot.cat \
        -no-emul-boot \
        -boot-load-size 4 \
        -boot-info-table \
        -eltorito-alt-boot \
        -e boot/grub/efi.img \
        -no-emul-boot \
        "${EXTRACT_DIR}" 2>/dev/null || true
    log_info "ISO生成完成 (使用xorriso)"
fi

# ============================================================
# 7. 清理
# ============================================================
log_step "[7/7] 清理构建文件..."
rm -rf "${BUILD_DIR}"

# ============================================================
# 完成
# ============================================================
echo ""
echo "============================================"
log_info "ISO构建完成!"
echo "============================================"
echo ""
if [ -f "${OUTPUT_ISO}" ]; then
    echo "ISO文件: ${OUTPUT_ISO}"
    echo "大小:    $(du -h ${OUTPUT_ISO} 2>/dev/null | cut -f1 || echo '未知')"
    echo "MD5:     $(md5sum ${OUTPUT_ISO} 2>/dev/null | cut -d' ' -f1 || echo '未知')"
else
    log_error "ISO文件生成失败"
    exit 1
fi
echo ""
echo -e "${GREEN}使用方法:${NC}"
echo "  1. 写入U盘:   sudo dd if=${OUTPUT_ISO} of=/dev/sdX bs=4M status=progress && sync"
echo "  2. 虚拟机:    直接挂载ISO作为CD-ROM启动"
echo "  3. 光盘刻录:  使用Brasero或K3b刻录到DVD"
echo ""
echo -e "${YELLOW}默认账号:${NC}"
echo "  Web面板: https://localhost:8443"
echo "  用户名: admin"
echo "  初始凭据请查看安装完成后的 /opt/gatekeeper/.initial_credentials"
echo ""
echo -e "${BLUE}安装说明:${NC}"
echo "  - 选择'自动安装'将全自动完成系统安装和GateKeeper部署"
echo "  - 选择'手动安装'可自定义分区和网络配置"
echo "============================================"
