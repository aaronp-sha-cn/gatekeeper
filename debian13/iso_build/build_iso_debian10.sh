#!/bin/bash
# ============================================================
# GateKeeper - ISO构建脚本 (Debian 10版本)
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
BUILD_DIR="${PROJECT_DIR}/iso_build/build"
ISO_NAME="gatekeeper-1.0.4-debian10.iso"

# ============================================================
# 1. 检查基础ISO
# ============================================================
log_step "[1/5] 检查Debian 10基础ISO..."
DEBIAN_ISO="${BUILD_DIR}/debian-base.iso"

if [ ! -f "${DEBIAN_ISO}" ]; then
    log_error "基础ISO不存在: ${DEBIAN_ISO}"
    exit 1
fi

log_info "基础ISO已存在: ${DEBIAN_ISO}"

# ============================================================
# 2. 使用7z提取ISO内容
# ============================================================
log_step "[2/5] 提取ISO内容..."
EXTRACT_DIR="${BUILD_DIR}/extract"

rm -rf "${EXTRACT_DIR}"
mkdir -p "${EXTRACT_DIR}"

# 使用7z提取ISO内容
if command -v 7z &> /dev/null; then
    7z x "${DEBIAN_ISO}" -o"${EXTRACT_DIR}" -y > /dev/null 2>&1
    log_info "ISO内容提取完成 (使用7z)"
else
    log_error "7z未安装，无法提取ISO"
    exit 1
fi

# 确保关键目录存在
mkdir -p "${EXTRACT_DIR}/isolinux"
mkdir -p "${EXTRACT_DIR}/install.amd"

# ============================================================
# 3. 准备GateKeeper安装包
# ============================================================
log_step "[3/5] 准备GateKeeper安装包..."

# 复制已打包好的tar.gz
cp "${BUILD_DIR}/gatekeeper.tar.gz" "${EXTRACT_DIR}/gatekeeper.tar.gz"
log_info "安装包准备完成"

# ============================================================
# 4. 集成preseed自动化配置
# ============================================================
log_step "[4/5] 集成preseed自动化配置..."
cp "${SCRIPT_DIR}/preseed.cfg" "${EXTRACT_DIR}/preseed.cfg"
cp "${SCRIPT_DIR}/late-command.sh" "${EXTRACT_DIR}/late-command.sh"

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
# 5. 重新生成ISO
# ============================================================
log_step "[5/5] 生成GateKeeper ISO..."
OUTPUT_ISO="${PROJECT_DIR}/${ISO_NAME}"

# 使用genisoimage生成ISO
cd "${EXTRACT_DIR}"

if command -v genisoimage &> /dev/null; then
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
elif command -v mkisofs &> /dev/null; then
    mkisofs \
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
    log_info "ISO生成完成 (使用mkisofs)"
elif command -v xorriso &> /dev/null; then
    xorriso -as mkisofs \
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
    log_info "ISO生成完成 (使用xorriso)"
elif python3 -c "import pycdlib" 2>/dev/null; then
    python3 "${SCRIPT_DIR}/build_iso_pycdlib.py" "${EXTRACT_DIR}" "${OUTPUT_ISO}"
    log_info "ISO生成完成 (使用pycdlib)"
else
    log_error "未找到ISO生成工具 (genisoimage/mkisofs/xorriso/pycdlib)"
    log_error "请安装: apt-get install -y genisoimage"
    exit 1
fi

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
